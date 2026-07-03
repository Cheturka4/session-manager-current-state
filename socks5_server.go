package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// SOCKS5 constants
const (
	socks5Version = 0x05

	authNone     = 0x00
	authNoAccept = 0xFF

	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess          = 0x00
	repNetUnreachable   = 0x03
	repHostUnreachable  = 0x04
	repConnRefused      = 0x05
	repCmdNotSupported  = 0x07
	repAddrNotSupported = 0x08
)

// ConnStats tracks per-connection metrics
type ConnStats struct {
	BytesUp   int64
	BytesDown int64
}

// SOCKS5Server is the main proxy server
type SOCKS5Server struct {
	listenAddr string
	sniPool    *StickyPool
	naiveMgr   *NaiveManager
	sessionMgr *SessionManager

	mu          sync.RWMutex
	activeConns map[string]*ConnStats
	totalConns  int64
}

func NewSOCKS5Server(listenAddr string, pool *StickyPool, naive *NaiveManager, session *SessionManager) *SOCKS5Server {
	return &SOCKS5Server{
		listenAddr:  listenAddr,
		sniPool:     pool,
		naiveMgr:    naive,
		sessionMgr:  session,
		activeConns: make(map[string]*ConnStats),
	}
}

func (s *SOCKS5Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("socks5 listen %s: %w", s.listenAddr, err)
	}
	defer ln.Close()
	log.Printf("[SOCKS5] Listening on %s", s.listenAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[SOCKS5] Accept error: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *SOCKS5Server) handleConn(conn net.Conn) {
	defer conn.Close()
	connID := conn.RemoteAddr().String()
	atomic.AddInt64(&s.totalConns, 1)
	stats := &ConnStats{}
	s.mu.Lock()
	s.activeConns[connID] = stats
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.activeConns, connID)
		s.mu.Unlock()
		log.Printf("[SOCKS5] [%s] closed ↑%s ↓%s",
			   connID,
	     humanBytes(atomic.LoadInt64(&stats.BytesUp)),
			   humanBytes(atomic.LoadInt64(&stats.BytesDown)),
		)
	}()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := s.handshake(conn); err != nil {
		log.Printf("[SOCKS5] [%s] handshake error: %v", connID, err)
		return
	}
	cmd, dst, dstPort, err := s.readRequest(conn)
	if err != nil {
		log.Printf("[SOCKS5] [%s] request error: %v", connID, err)
		return
	}
	if cmd == cmdUDPAssociate {
		s.handleUDPAssociate(conn)
		return
	}
	log.Printf("[SOCKS5] [%s] → %s:%d", connID, dst, dstPort)

	// Direct-bypass для банков/госуслуг — см. domains_direct.go.
	// Идёт МИМО всего proxy-стека: без SNI-маскировки, без naive, без Frankfurt.
	if IsDirectDomain(dst) {
		s.handleDirect(conn, connID, dst, dstPort, stats)
		return
	}

	appType := ClassifyByHost(dst)
	profile := profiles[appType]
	sni := s.sniPool.PickForApp(appType)
	log.Printf("[SOCKS5] [%s] app=%s sni=%s profile=min%ds", connID, appType, sni, profile.MinDuration)
	go s.sessionMgr.preDNS(sni)
	var upstreamAddr string
	upstreamAddr, err = s.naiveMgr.GetUpstreamForApp(sni, appType)
	if err != nil {
		log.Printf("[SOCKS5] [%s] no upstream for sni=%s: %v", connID, sni, err)
		s.writeReply(conn, repNetUnreachable, "0.0.0.0", 0)
		return
	}
	upstream, err := net.DialTimeout("tcp", upstreamAddr, 10*time.Second)
	if err != nil {
		log.Printf("[SOCKS5] [%s] upstream dial error: %v", connID, err)
		s.writeReply(conn, repConnRefused, "0.0.0.0", 0)
		return
	}
	defer upstream.Close()
	if tc, ok := upstream.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetReadBuffer(256 * 1024)
		tc.SetWriteBuffer(256 * 1024)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	if err := socks5Connect(upstream, dst, dstPort); err != nil {
		log.Printf("[SOCKS5] [%s] upstream CONNECT error: %v", connID, err)
		s.writeReply(conn, repNetUnreachable, "0.0.0.0", 0)
		return
	}
	if err := s.writeReply(conn, repSuccess, "0.0.0.0", 0); err != nil {
		return
	}
	conn.SetDeadline(time.Time{})
	upstream.SetDeadline(time.Time{})
	s.pipe(conn, upstream, stats, profile)
}

func (s *SOCKS5Server) handleDirect(conn net.Conn, connID, dst string, dstPort uint16, stats *ConnStats) {
	log.Printf("[SOCKS5] [%s] DIRECT (sensitive domain, bypass proxy) → %s:%d", connID, dst, dstPort)

	target := dst
	if ip := net.ParseIP(dst); ip == nil {
		// dst — домен, не IP: резолвим через ResolveDirect (DoH к Яндексу,
		// см. domains_direct.go), а не через системный DNS PC.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := ResolveDirect(ctx, dst)
		cancel()
		if err != nil || len(ips) == 0 {
			log.Printf("[SOCKS5] [%s] direct resolve failed for %s: %v", connID, dst, err)
			s.writeReply(conn, repHostUnreachable, "0.0.0.0", 0)
			return
		}
		target = ips[0].String()
	}

	directConn, err := net.DialTimeout("tcp", net.JoinHostPort(target, strconv.Itoa(int(dstPort))), 10*time.Second)
	if err != nil {
		log.Printf("[SOCKS5] [%s] direct dial error: %v", connID, err)
		s.writeReply(conn, repConnRefused, "0.0.0.0", 0)
		return
	}
	defer directConn.Close()
	if tc, ok := directConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	if err := s.writeReply(conn, repSuccess, "0.0.0.0", 0); err != nil {
		return
	}
	conn.SetDeadline(time.Time{})
	// Без профиля/SNI-логики — это прозрачный relay, телефон видит настоящий
	// сертификат банка/госуслуги, как будто прокси тут вообще не было.
	s.pipe(conn, directConn, stats, SessionProfile{})
}

func (s *SOCKS5Server) handshake(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	for _, m := range methods {
		if m == authNone {
			_, err := conn.Write([]byte{socks5Version, authNone})
			return err
		}
	}
	conn.Write([]byte{socks5Version, authNoAccept})
	return fmt.Errorf("no acceptable auth method")
}

func (s *SOCKS5Server) readRequest(conn net.Conn) (cmd byte, host string, port uint16, err error) {
	header := make([]byte, 4)
	if _, err = io.ReadFull(conn, header); err != nil {
		return
	}
	if header[0] != socks5Version {
		err = fmt.Errorf("bad version in request")
		return
	}
	cmd = header[1]
	if cmd != cmdConnect && cmd != cmdUDPAssociate {
		s.writeReply(conn, repCmdNotSupported, "0.0.0.0", 0)
		err = fmt.Errorf("unsupported command: %d", cmd)
		return
	}
	switch header[3] {
		case atypIPv4:
			addr := make([]byte, 4)
			if _, err = io.ReadFull(conn, addr); err != nil {
				return
			}
			host = net.IP(addr).String()
		case atypDomain:
			lenBuf := make([]byte, 1)
			if _, err = io.ReadFull(conn, lenBuf); err != nil {
				return
			}
			domain := make([]byte, int(lenBuf[0]))
			if _, err = io.ReadFull(conn, domain); err != nil {
				return
			}
			host = string(domain)
		case atypIPv6:
			addr := make([]byte, 16)
			if _, err = io.ReadFull(conn, addr); err != nil {
				return
			}
			host = "[" + net.IP(addr).String() + "]"
		default:
			s.writeReply(conn, repAddrNotSupported, "0.0.0.0", 0)
			err = fmt.Errorf("unsupported atyp: %d", header[3])
			return
	}
	portBuf := make([]byte, 2)
	if _, err = io.ReadFull(conn, portBuf); err != nil {
		return
	}
	port = binary.BigEndian.Uint16(portBuf)
	return
}

func (s *SOCKS5Server) writeReply(conn net.Conn, rep byte, bindAddr string, bindPort uint16) error {
	ip := net.ParseIP(bindAddr).To4()
	if ip == nil {
		ip = net.IPv4zero.To4()
	}
	_, err := conn.Write([]byte{
		socks5Version, rep, 0x00, atypIPv4,
		ip[0], ip[1], ip[2], ip[3],
		byte(bindPort >> 8), byte(bindPort),
	})
	return err
}

func socks5Connect(conn net.Conn, host string, port uint16) error {
	if _, err := conn.Write([]byte{socks5Version, 1, authNone}); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != authNone {
		return fmt.Errorf("upstream rejected no-auth: %d", resp[1])
	}
	hostBytes := []byte(host)
	req := make([]byte, 0, 7+len(hostBytes))
	req = append(req, socks5Version, cmdConnect, 0x00, atypDomain)
	req = append(req, byte(len(hostBytes)))
	req = append(req, hostBytes...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}
	replyHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, replyHeader); err != nil {
		return err
	}
	if replyHeader[1] != repSuccess {
		return fmt.Errorf("upstream CONNECT failed: rep=%d", replyHeader[1])
	}
	switch replyHeader[3] {
		case atypIPv4:
			io.ReadFull(conn, make([]byte, 6))
		case atypDomain:
			lb := make([]byte, 1)
			io.ReadFull(conn, lb)
			io.ReadFull(conn, make([]byte, int(lb[0])+2))
		case atypIPv6:
			io.ReadFull(conn, make([]byte, 18))
	}
	return nil
}

func (s *SOCKS5Server) handleUDPAssociate(conn net.Conn) {
	defer conn.Close()
	udpLn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		conn.Write(socks5ErrReply(0x01))
		return
	}
	defer udpLn.Close()
	relayPort := udpLn.LocalAddr().(*net.UDPAddr).Port
	_, err = conn.Write([]byte{
		0x05, 0x00, 0x00, 0x01,
		127, 0, 0, 1,
		byte(relayPort >> 8), byte(relayPort & 0xff),
	})
	if err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 1)
		for {
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			if _, err := conn.Read(b); err != nil {
				return
			}
		}
	}()
	type udpRelay struct {
		sync.Mutex
		upUDP *net.UDPConn
		upCtl net.Conn
	}
	var (
		relaysMu sync.RWMutex
		relays   = make(map[string]*udpRelay)
	)
	inBuf := make([]byte, 65535)
	for {
		select {
		case <-done:
			return
		default:
		}
		udpLn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, clientAddr, err := udpLn.ReadFromUDP(inBuf)
		if err != nil {
			return
		}
		dstHost, dstPort, hdrLen, ok := udpParseHeader(inBuf[:n])
		if !ok {
			continue
		}
		payload := make([]byte, n-hdrLen)
		copy(payload, inBuf[hdrLen:n])
		dstKey := fmt.Sprintf("%s:%d", dstHost, dstPort)
		relaysMu.RLock()
		r := relays[dstKey]
		relaysMu.RUnlock()
		if r == nil {
			r = &udpRelay{}
			relaysMu.Lock()
			if existing := relays[dstKey]; existing != nil {
				r = existing
			} else {
				relays[dstKey] = r
			}
			relaysMu.Unlock()
		}
		r.Lock()
		if r.upUDP == nil {
			appType := ClassifyByHost(dstHost)
			pickedSNI := s.sniPool.PickForApp(appType)
			naiveAddr, err := s.naiveMgr.GetUpstreamForApp(pickedSNI, appType)
			if err != nil {
				r.Unlock()
				log.Printf("[UDP] no upstream for %s: %v", dstKey, err)
				continue
			}
			upCtl, upUDP, err := udpDialNaive(naiveAddr, dstHost, dstPort)
			if err != nil {
				r.Unlock()
				log.Printf("[UDP] dial failed for %s: %v", dstKey, err)
				continue
			}
			r.upCtl = upCtl
			r.upUDP = upUDP
			go func(r *udpRelay, ca *net.UDPAddr) {
				buf := make([]byte, 65535)
				for {
					r.Lock()
					uc := r.upUDP
					r.Unlock()
					if uc == nil {
						return
					}
					uc.SetReadDeadline(time.Now().Add(5 * time.Minute))
					rn, _, err := uc.ReadFromUDP(buf)
					if err != nil {
						return
					}
					udpLn.WriteToUDP(buf[:rn], ca)
				}
			}(r, clientAddr)
		}
		pkt := udpBuildHeader(dstHost, dstPort)
		pkt = append(pkt, payload...)
		if r.upUDP != nil {
			r.upUDP.Write(pkt)
		}
		r.Unlock()
	}
}

func (s *SOCKS5Server) pipe(conn, upstream net.Conn, stats *ConnStats, profile SessionProfile) {
	done := make(chan struct{}, 2)
	dlBufSize := 256 * 1024
	ulBufSize := 256 * 1024
	if profile.UploadRatio <= 0.02 {
		dlBufSize = 256 * 1024
	}
	if profile.UploadRatio >= 0.5 {
		ulBufSize = 256 * 1024
		dlBufSize = 256 * 1024
	}
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, dlBufSize)
		for {
			n, err := upstream.Read(buf)
			if n > 0 {
				if _, werr := conn.Write(buf[:n]); werr != nil {
					return
				}
				total := atomic.AddInt64(&stats.BytesDown, int64(n))
				if profile.MaxBytes > 0 &&
					total+atomic.LoadInt64(&stats.BytesUp) > profile.MaxBytes {
						// Раньше здесь было безусловное conn.Close()/upstream.Close() —
						// это рвало ЛЮБУЮ закачку больше профильного MaxBytes на середине
						// (например любой файл >50MB на профиле browser). Теперь проверяем
						// upload ratio: если он низкий — это явно легитимная сустейн-закачка
						// (файл, видео, обновление игры без явного домена в классификаторе),
						// а не аномальный по объёму браузерный сёрфинг. Не убиваем такую
						// сессию, просто перестаём считать её "подозрительной по объёму".
						upBytes := atomic.LoadInt64(&stats.BytesUp)
						upRatio := float64(upBytes) / float64(total+upBytes+1)
						if upRatio >= 0.05 {
							conn.Close()
							upstream.Close()
							return
						}
					}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, ulBufSize)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if _, werr := upstream.Write(buf[:n]); werr != nil {
					return
				}
				atomic.AddInt64(&stats.BytesUp, int64(n))
			}
			if err != nil {
				return
			}
		}
	}()
	<-done
	conn.Close()
	upstream.Close()
	<-done
}

func (s *SOCKS5Server) ActiveConns() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.activeConns)
}

func humanBytes(b int64) string {
	switch {
		case b >= 1<<20:
			return strconv.FormatFloat(float64(b)/float64(1<<20), 'f', 1, 64) + "MB"
		case b >= 1<<10:
			return strconv.FormatFloat(float64(b)/float64(1<<10), 'f', 1, 64) + "KB"
		default:
			return strconv.FormatInt(b, 10) + "B"
	}
}

func udpParseHeader(b []byte) (host string, port int, hdrLen int, ok bool) {
	if len(b) < 4 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
		return
	}
	switch b[3] {
		case 0x01:
			if len(b) < 10 {
				return
			}
			host = net.IP(b[4:8]).String()
			port = int(b[8])<<8 | int(b[9])
			hdrLen = 10
		case 0x03:
			if len(b) < 5 {
				return
			}
			dl := int(b[4])
			if len(b) < 5+dl+2 {
				return
			}
			host = string(b[5 : 5+dl])
			port = int(b[5+dl])<<8 | int(b[5+dl+1])
			hdrLen = 5 + dl + 2
		case 0x04:
			if len(b) < 22 {
				return
			}
			host = net.IP(b[4:20]).String()
			port = int(b[20])<<8 | int(b[21])
			hdrLen = 22
		default:
			return
	}
	ok = true
	return
}

func udpBuildHeader(host string, port int) []byte {
	hdr := []byte{0x00, 0x00, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			hdr = append(hdr, 0x01)
			hdr = append(hdr, ip4...)
		} else {
			hdr = append(hdr, 0x04)
			hdr = append(hdr, ip.To16()...)
		}
	} else {
		hdr = append(hdr, 0x03, byte(len(host)))
		hdr = append(hdr, host...)
	}
	return append(hdr, byte(port>>8), byte(port&0xff))
}

func udpDialNaive(naiveAddr, dstHost string, dstPort int) (net.Conn, *net.UDPConn, error) {
	ctl, err := net.DialTimeout("tcp", naiveAddr, 5*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("dial naive %s: %w", naiveAddr, err)
	}
	if _, err = ctl.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		ctl.Close()
		return nil, nil, err
	}
	resp := make([]byte, 2)
	if _, err = io.ReadFull(ctl, resp); err != nil || resp[0] != 0x05 || resp[1] != 0x00 {
		ctl.Close()
		return nil, nil, fmt.Errorf("socks5 auth rejected: %v", err)
	}
	req := buildSocks5Request(0x03, dstHost, dstPort)
	if _, err = ctl.Write(req); err != nil {
		ctl.Close()
		return nil, nil, err
	}
	relayHost, relayPort, err := readSocks5Reply(ctl)
	if err != nil {
		ctl.Close()
		return nil, nil, fmt.Errorf("socks5 reply: %w", err)
	}
	udpAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", relayHost, relayPort))
	if err != nil {
		ctl.Close()
		return nil, nil, err
	}
	udpConn, err := net.DialUDP("udp4", nil, udpAddr)
	if err != nil {
		ctl.Close()
		return nil, nil, err
	}
	return ctl, udpConn, nil
}

func socks5ErrReply(code byte) []byte {
	return []byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
}

func buildSocks5Request(cmd byte, host string, port int) []byte {
	req := []byte{socks5Version, cmd, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, atypIPv4)
			req = append(req, ip4...)
		} else {
			req = append(req, atypIPv6)
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, atypDomain, byte(len(host)))
		req = append(req, host...)
	}
	return append(req, byte(port>>8), byte(port&0xff))
}

func readSocks5Reply(conn net.Conn) (string, int, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return "", 0, err
	}
	if hdr[1] != repSuccess {
		return "", 0, fmt.Errorf("SOCKS5 reply error code=%d", hdr[1])
	}
	var host string
	switch hdr[3] {
		case atypIPv4:
			addr := make([]byte, 4)
			if _, err := io.ReadFull(conn, addr); err != nil {
				return "", 0, err
			}
			host = net.IP(addr).String()
		case atypDomain:
			lb := make([]byte, 1)
			if _, err := io.ReadFull(conn, lb); err != nil {
				return "", 0, err
			}
			domain := make([]byte, int(lb[0]))
			if _, err := io.ReadFull(conn, domain); err != nil {
				return "", 0, err
			}
			host = string(domain)
		case atypIPv6:
			addr := make([]byte, 16)
			if _, err := io.ReadFull(conn, addr); err != nil {
				return "", 0, err
			}
			host = net.IP(addr).String()
		default:
			return "", 0, fmt.Errorf("unknown atyp=%d in reply", hdr[3])
	}
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", 0, err
	}
	return host, int(binary.BigEndian.Uint16(portBuf)), nil
}
