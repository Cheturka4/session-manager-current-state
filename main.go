package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	// ── Флаги Session Manager ─────────────────────────────────────────────────
	listenAddr := flag.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
	naiveBin   := flag.String("naive", "./naive", "Path to naive binary")
	upstream   := flag.String("upstream", "", "Upstream proxy URL (https://user:pass@host)")
	configDir  := flag.String("cfgdir", "/tmp/owo-naive-cfgs", "Directory for per-SNI naive configs")
	basePort   := flag.Int("baseport", 11000, "Starting port for naive instances")

	// ── Флаги Relay режима ────────────────────────────────────────────────────
	relay        := flag.Bool("relay", false, "Enable relay mode: accept incoming client connections")
	relayListen  := flag.String("relay-listen", "127.0.0.1:1081", "Relay SOCKS5 listen addr (Caddy forwards here)")
	relayIP      := flag.String("relay-ip", "", "Public IP of this relay node (for VK registry)")
	relayPort    := flag.Int("relay-port", 443, "Public port of this relay node (for VK registry)")
	relayPubkey  := flag.String("relay-pubkey", "", "REALITY fingerprint pubkey (base64, from Caddy cert)")
	relayKind    := flag.String("relay-kind", "client", "Node kind: core|server|client")
	vkToken      := flag.String("vk-token", "", "VK API token for relay registry")
	vkGroup      := flag.Int64("vk-group", 0, "VK Group ID for relay registry")
	vkKey        := flag.String("vk-key", "", "Shared HMAC key matching bot SHARED_KEY")

	flag.Parse()

	if *upstream == "" {
		log.Fatal("[main] --upstream required: https://owo:pass@proxy.owocloud.online")
	}

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	log.Printf("[main] OwOCloak Session Manager starting")
	log.Printf("[main] listen=%s naive=%s relay=%v", *listenAddr, *naiveBin, *relay)

	// ── Инициализация компонентов ─────────────────────────────────────────────
	pool       := NewStickyPool(defaultPool)
	sessionMgr := NewSessionManager()

	naiveMgr, err := NewNaiveManager(*naiveBin, *upstream, *configDir, *basePort)
	if err != nil {
		log.Fatalf("[main] NaiveManager init: %v", err)
	}

	// Прогрев IoT инстансов
	for _, sni := range []string{
		"ipv4-internet.yandex.net",
		"ipv6-internet.yandex.net",
		"internet.yandex.ru",
	} {
		naiveMgr.GetUpstreamForApp(sni, AppIoT)
	}

	naiveMgr.StartGC(2*time.Minute, 5*time.Minute)

	// ── Cloudflare Top1000 updater ────────────────────────────────────────────
	go func() {
		if err := fetchCloudflareTop1000(); err != nil {
			log.Printf("[cloudflare] initial fetch error: %v", err)
		} else {
			log.Printf("[cloudflare] domains updated")
		}
		t := time.NewTicker(7 * 24 * time.Hour)
		defer t.Stop()
		for range t.C {
			if err := fetchCloudflareTop1000(); err != nil {
				log.Printf("[cloudflare] update error: %v", err)
			} else {
				log.Printf("[cloudflare] domains refreshed")
			}
		}
	}()

	// ── SOCKS5 сервер ─────────────────────────────────────────────────────────
	server := NewSOCKS5Server(*listenAddr, pool, naiveMgr, sessionMgr)
	go func() {
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("[main] SOCKS5: %v", err)
		}
	}()

	// ── Relay режим ───────────────────────────────────────────────────────────
	var cancelVK context.CancelFunc
	var vkc *VKClient

	if *relay {
		// Валидация флагов
		switch {
		case *relayIP == "":
			log.Fatal("[relay] --relay-ip required in relay mode")
		case *vkToken == "":
			log.Fatal("[relay] --vk-token required in relay mode")
		case *vkGroup == 0:
			log.Fatal("[relay] --vk-group required in relay mode")
		case *vkKey == "":
			log.Fatal("[relay] --vk-key required in relay mode")
		}

		vkc = NewVKClient(*vkToken, *vkGroup, *vkKey, *relayIP, *relayPort, *relayPubkey, *relayKind)

		// Зарегистрироваться в VK Bot
		if err := vkc.Register(); err != nil {
			log.Fatalf("[relay] VK register failed: %v", err)
		}

		// Фоновый пинг каждые 60с
		var ctx context.Context
		ctx, cancelVK = context.WithCancel(context.Background())
		vkc.StartPingLoop(ctx)

		// Relay SOCKS5 сервер
		relaySrv := NewRelayServer(*relayListen, *listenAddr, vkc)
		go func() {
			if err := relaySrv.ListenAndServe(); err != nil {
				log.Fatalf("[relay] %v", err)
			}
		}()

		// Status для relay
		go func() {
			t := time.NewTicker(30 * time.Second)
			defer t.Stop()
			for range t.C {
				log.Printf("[relay] active_relay_conns=%d", relaySrv.ActiveConns())
			}
		}()

		log.Printf("[relay] active: public=%s:%d  internal=%s  kind=%s",
			*relayIP, *relayPort, *relayListen, *relayKind)
	}

	// ── Status ticker ─────────────────────────────────────────────────────────
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for range t.C {
			instances := naiveMgr.Status()
			log.Printf("[status] active_conns=%d naive_instances=%d total_served=%d",
				server.ActiveConns(), len(instances), server.totalConns)
			for _, inst := range instances {
				log.Printf("[status]   sni=%-25s port=%d ready=%v idle=%s",
					inst.SNI, inst.Port, inst.Ready,
					time.Since(inst.LastUsed).Round(time.Second))
			}
		}
	}()

	// ── Graceful shutdown ─────────────────────────────────────────────────────
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Printf("[main] Shutting down...")

	if *relay && vkc != nil {
		if cancelVK != nil {
			cancelVK()
		}
		if err := vkc.Unregister(); err != nil {
			log.Printf("[relay] unregister error: %v", err)
		}
	}

	naiveMgr.StopAll()
	log.Printf("[main] Bye")
}
