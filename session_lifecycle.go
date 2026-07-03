package main

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"time"
)

type SessionState int

const (
	StateIdle    SessionState = iota
	StateActive
	StatePausing
)

type Session struct {
	ID        string
	SNI       string
	AppType   AppType
	State     SessionState
	StartedAt time.Time
	EndsAt    time.Time
	cancel    context.CancelFunc
}

type SessionManager struct {
	pool     *SNIPool
	sessions map[string]*Session
	dnsCache map[string]time.Time // host → последний DNS-запрос
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		pool:     defaultPool,
		sessions: make(map[string]*Session),
		dnsCache: make(map[string]time.Time),
	}
}


// activityMultiplier — браузер активнее в определённое время суток
// DPI обученный на реальных пользователях ожидает такой паттерн

func (sm *SessionManager) preDNS(sni string) {
    last, ok := sm.dnsCache[sni]
    if ok && time.Since(last) < 90*time.Second {
        return
    }

    // Jitter масштабируется по времени суток
    // Ночью браузер "медленнее" — пользователь устал
    mult := activityMultiplier()
    baseJitter := 40 + rand.Intn(110)  // 40–150ms базовый диапазон
    jitter := time.Duration(float64(baseJitter)/mult) * time.Millisecond
    time.Sleep(jitter)

    go func() {
        addrs, err := net.LookupHost(sni)
        if err == nil {
            fmt.Printf("[DNS] %s → %v\n", sni, addrs[0])
        }
        sm.dnsCache[sni] = time.Now()
    }()
}

// Jitter — случайная задержка для имитации человека
func humanJitter(minMs, maxMs int) time.Duration {
	ms := minMs + rand.Intn(maxMs-minMs)
	return time.Duration(ms) * time.Millisecond
}

// Открываем новую сессию под конкретный destination
func (sm *SessionManager) OpenSession(destHost string) *Session {
	appType := ClassifyByHost(destHost)
	profile := GetProfile(appType)
	sni := sm.pool.PickForApp(AppType(profile.SNIAppType))

	// DNS до соединения — как настоящий браузер
	sm.preDNS(sni)
	// Человеческая задержка 50-200мс после DNS
	time.Sleep(humanJitter(50, 200))

	duration := time.Duration(
		profile.MinDuration+rand.Intn(profile.MaxDuration-profile.MinDuration),
	) * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), duration)

	session := &Session{
		ID:        fmt.Sprintf("%s-%d", sni, time.Now().UnixMilli()),
		SNI:       sni,
		AppType:   appType,
		State:     StateActive,
		StartedAt: time.Now(),
		EndsAt:    time.Now().Add(duration),
		cancel:    cancel,
	}
	sm.sessions[session.ID] = session

	fmt.Printf("[Session] OPEN  %s → SNI=%s app=%s duration=%s\n",
		destHost, sni, appType, duration.Round(time.Second))

	// Автоматически закрываем по таймеру и делаем паузу
	go sm.lifecycleWorker(ctx, session, profile)

	return session
}

func (sm *SessionManager) lifecycleWorker(
	ctx context.Context, s *Session, profile SessionProfile,
) {
	<-ctx.Done() // ждём истечения таймера сессии

	s.State = StatePausing
	fmt.Printf("[Session] PAUSE %s (SNI=%s)\n", s.ID, s.SNI)

	// Пауза как у браузера между сессиями
	pause := time.Duration(
		profile.PauseMin+rand.Intn(profile.PauseMax-profile.PauseMin),
	) * time.Second
	time.Sleep(pause)

	s.State = StateIdle
	fmt.Printf("[Session] IDLE  %s → готов к новой сессии\n", s.ID)
}

func (sm *SessionManager) CloseSession(id string) {
	if s, ok := sm.sessions[id]; ok {
		s.cancel()
		delete(sm.sessions, id)
		fmt.Printf("[Session] CLOSE %s\n", id)
	}
}
