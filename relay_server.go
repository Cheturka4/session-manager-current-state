package main

import (
	"crypto/subtle"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// RelayServer принимает входящие SOCKS5-соединения от клиентов OwOCloak
// и форвардит их через локальный Session Manager → Frankfurt → Интернет
//
// Цепочка:
//   Клиент [OwOCloak] → (TLS, NaiveProxy) → Caddy(локальный) → RelayServer(SOCKS5) → SessionManager(SOCKS5) → Frankfurt
//
// RelayServer — это средний слой. Caddy (отдельный процесс) терминирует TLS
// и форвардит расшифрованный SOCKS5 на наш listenAddr.
type RelayServer struct {
	listenAddr  string // где слушаем входящие, e.g. "127.0.0.1:1081"
	socks5Addr  string // Session Manager SOCKS5, e.g. "127.0.0.1:1080"
	// token -- тот же секрет, что и у основного SOCKS5Server. Без него этот
	// листенер был чистым обходом токена на 1080: кто угодно мог подключиться
	// сюда вместо 1080 и получить полный доступ без единого байта авторизации.
	token       []byte
	vkClient    *VKClient

	mu          sync.Mutex
	activeConns int64
	totalServed int64
}

func NewRelayServer(listenAddr, socks5Addr string, token []byte, vk *VKClient) *RelayServer {
	return &RelayServer{
		listenAddr: listenAddr,
		socks5Addr: socks5Addr,
		token:      token,
		vkClient:   vk,
	}
}

func (r *RelayServer) ListenAndServe() error {
	ln, err := net.Listen("tcp", r.listenAddr)
	if err != nil {
		return fmt.Errorf("relay listen %s: %w", r.listenAddr, err)
	}
	defer ln.Close()
	log.Printf("[Relay] Listening on %s  →  via Session Manager %s", r.listenAddr, r.socks5Addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[Relay] Accept error: %v", err)
			continue
		}
		atomic.AddInt64(&r.totalServed, 1)
		atomic.AddInt64(&r.activeConns, 1)
		go r.handleConn(conn)
	}
}

func (r *RelayServer) handleConn(clientConn net.Conn) {
	defer func() {
		clientConn.Close()
		atomic.AddInt64(&r.activeConns, -1)
	}()

	clientConn.SetDeadline(time.Now().Add(30 * time.Second))

	// ── SOCKS5 handshake с входящим клиентом ─────────────────────────────────
	// Caddy уже терминировал TLS и говорит с нами plain SOCKS5.
	// [OwO fix] Раньше здесь безусловно принимался authNone -- то есть
	// ЛЮБОЙ, кто достанет до этого порта напрямую (минуя Caddy), получал
	// полный доступ в обход токена, который мы только что поставили на 1080.
	// Теперь требуем тот же токен и здесь.
	header := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		log.Printf("[Relay] %s: not SOCKS5 (version=%d)", clientConn.RemoteAddr(), header[0])
		return
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(clientConn, methods); err != nil {
		return
	}
	if len(r.token) == 0 {
		clientConn.Write([]byte{0x05, 0x00})
	} else {
		hasPassword := false
		for _, m := range methods {
			if m == authPassword {
				hasPassword = true
				break
			}
		}
		if !hasPassword {
			clientConn.Write([]byte{0x05, authNoAccept})
			log.Printf("[Relay] %s: client did not offer username/password auth", clientConn.RemoteAddr())
			return
		}
		if _, err := clientConn.Write([]byte{0x05, authPassword}); err != nil {
			return
		}
		sub := make([]byte, 2)
		if _, err := io.ReadFull(clientConn, sub); err != nil {
			return
		}
		if sub[0] != userpassVersion {
			clientConn.Write([]byte{userpassVersion, userpassFailure})
			return
		}
		uname := make([]byte, int(sub[1]))
		if _, err := io.ReadFull(clientConn, uname); err != nil {
			return
		}
		plenBuf := make([]byte, 1)
		if _, err := io.ReadFull(clientConn, plenBuf); err != nil {
			return
		}
		passwd := make([]byte, int(plenBuf[0]))
		if _, err := io.ReadFull(clientConn, passwd); err != nil {
			return
		}
		if subtle.ConstantTimeCompare(passwd, r.token) != 1 {
			clientConn.Write([]byte{userpassVersion, userpassFailure})
			log.Printf("[Relay] auth failed for remote %s", clientConn.RemoteAddr())
			return
		}
		clientConn.Write([]byte{userpassVersion, userpassSuccess})
	}

	// ── Читаем CONNECT запрос ─────────────────────────────────────────────────
	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, reqHdr); err != nil {
		return
	}
	if reqHdr[1] != 0x01 { // только CONNECT
		clientConn.Write(relayErrReply(0x07)) // CMD_NOT_SUPPORTED
		return
	}

	var destHost string
	switch reqHdr[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(clientConn, addr); err != nil {
			return
		}
		destHost = net.IP(addr).String()
	case 0x03: // Domain
		lb := make([]byte, 1)
		if _, err := io.ReadFull(clientConn, lb); err != nil {
			return
		}
		domain := make([]byte, lb[0])
		if _, err := io.ReadFull(clientConn, domain); err != nil {
			return
		}
		destHost = string(domain)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(clientConn, addr); err != nil {
			return
		}
		destHost = "[" + net.IP(addr).String() + "]"
	default:
		clientConn.Write(relayErrReply(0x08)) // ATYP_NOT_SUPPORTED
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, portBuf); err != nil {
		return
	}
	destPort := uint16(portBuf[0])<<8 | uint16(portBuf[1])

	log.Printf("[Relay] %s → %s:%d", clientConn.RemoteAddr(), destHost, destPort)

	// ── Подключиться к Session Manager SOCKS5 ────────────────────────────────
	upstream, err := net.DialTimeout("tcp", r.socks5Addr, 10*time.Second)
	if err != nil {
		log.Printf("[Relay] cannot reach Session Manager at %s: %v", r.socks5Addr, err)
		clientConn.Write(relayErrReply(0x03)) // NET_UNREACHABLE
		return
	}
	defer upstream.Close()

	// SOCKS5 CONNECT через Session Manager (функция из socks5_server.go)
	if err := socks5Connect(upstream, destHost, destPort, r.token); err != nil {
		log.Printf("[Relay] Session Manager CONNECT %s:%d failed: %v", destHost, destPort, err)
		clientConn.Write(relayErrReply(0x04)) // HOST_UNREACHABLE
		return
	}

	// ── Сообщить клиенту: успех ───────────────────────────────────────────────
	if _, err := clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// Снять deadline для фазы данных
	clientConn.SetDeadline(time.Time{})
	upstream.SetDeadline(time.Time{})

	// TCP буферы
	if tc, ok := upstream.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetReadBuffer(256 * 1024)
		tc.SetWriteBuffer(256 * 1024)
	}
	if tc, ok := clientConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	// ── Двунаправленный pipe ──────────────────────────────────────────────────
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 64*1024)
		io.CopyBuffer(upstream, clientConn, buf)
		done <- struct{}{}
	}()
	go func() {
		buf := make([]byte, 64*1024)
		io.CopyBuffer(clientConn, upstream, buf)
		done <- struct{}{}
	}()
	<-done
	clientConn.Close()
	upstream.Close()
	<-done
}

func (r *RelayServer) ActiveConns() int64 {
	return atomic.LoadInt64(&r.activeConns)
}

func relayErrReply(code byte) []byte {
	return []byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
}
