package main

import (
	"log"
	"math"
	"math/rand"
	"sync"
	"time"
)

// SNIEntry — запись в пуле маскировочных SNI.
// Host — российский/белосписочный домен, который будет виден ТСПУ в ClientHello.
// Трафик НЕ идёт на этот хост — только поле SNI в TLS-рукопожатии.
type SNIEntry struct {
	Host    string
	Weight  int
	AppType string // совпадает с AppType.String()
}

// SNICounter — скользящее окно подсчёта соединений на SNI.
// Не даёт одному SNI появляться слишком часто — имитирует реальный браузер,
// который не ходит на один домен 50 раз в минуту.
type SNICounter struct {
	mu           sync.Mutex
	counts       map[string][]time.Time
	maxPerWindow int
	window       time.Duration
}

// Allow возвращает true и регистрирует соединение, если лимит не превышен.
func (c *SNICounter) Allow(host string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-c.window)

	// Чистим старые записи
	fresh := c.counts[host][:0]
	for _, t := range c.counts[host] {
		if t.After(cutoff) {
			fresh = append(fresh, t)
		}
	}
	c.counts[host] = fresh

	if len(fresh) >= c.maxPerWindow {
		return false
	}
	c.counts[host] = append(c.counts[host], now)
	return true
}

// RecentCount возвращает количество соединений к хосту за последнее окно.
func (c *SNICounter) RecentCount(host string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-c.window)
	count := 0
	for _, t := range c.counts[host] {
		if t.After(cutoff) {
			count++
		}
	}
	return count
}

// SNIPool — пул маскировочных SNI с весовым выбором и per-SNI rate limiting.
type SNIPool struct {
	entries []SNIEntry
	counter *SNICounter
	total   int
}

// defaultPool — пул SNI по умолчанию.
//
// Правила выбора доменов:
//   1. Только домены из российского белого списка (РКН/Роскомсвобода).
//   2. Домен должен отдавать реальный TLS-ответ (не пустую страницу).
//   3. Вес пропорционален реальной частоте посещений (Яндекс.Метрика топ-100).
//   4. maxPerWindow=3 за 60с — имитирует поведение одной вкладки браузера.
var defaultPool = &SNIPool{
	entries: []SNIEntry{

		// ── browser ───────────────────────────────────────────────────────────
		// Топ российских сайтов. Высокий вес = чаще появляются в ClientHello.
		//
		// ВАЖНО: банки и госуслуги (sberbank.ru/tbank.ru/gosuslugi.ru) убраны
		// отсюда намеренно. Маскировка под них означала бы, что в случае
		// коллизии с реальным визитом пользователя на эти сайты возможна
		// путаница/конфликт состояния TLS-сессии — а такой риск для
		// чувствительного трафика пользователя недопустим. Реальный трафик
		// к этим доменам теперь обрабатывается через IsDirectDomain()
		// (см. domains_direct.go) и идёт напрямую, минуя весь этот пул.
		{Host: "ya.ru",          Weight: 30, AppType: "browser"},
		{Host: "yandex.ru",      Weight: 15, AppType: "browser"},
		{Host: "wildberries.ru", Weight: 25, AppType: "browser"},
		{Host: "ozon.ru",        Weight: 20, AppType: "browser"},
		{Host: "avito.ru",       Weight: 18, AppType: "browser"},
		{Host: "lenta.ru",       Weight: 12, AppType: "browser"},
		{Host: "rbc.ru",         Weight: 10, AppType: "browser"},
		{Host: "kommersant.ru",  Weight: 8,  AppType: "browser"},
		// Добавлено из whitelist.txt (hxehex/russia-mobile-internet-whitelist) —
		// подтверждено сторонним сканированием как реально проходящее на белых списках.
		{Host: "dzen.ru",   Weight: 14, AppType: "browser"},
		{Host: "gazeta.ru", Weight: 6,  AppType: "browser"},
		{Host: "kp.ru",     Weight: 8,  AppType: "browser"},
		{Host: "rambler.ru", Weight: 6, AppType: "browser"},
		{Host: "auto.ru",   Weight: 8,  AppType: "browser"},
		{Host: "tutu.ru",   Weight: 6,  AppType: "browser"},

		// ── messaging ─────────────────────────────────────────────────────────
		// VK — крупнейшая соцсеть РФ. mail.ru и ok.ru — в топ-10 по трафику.
		{Host: "vk.com",  Weight: 20, AppType: "messaging"},
		{Host: "vk.ru",   Weight: 10, AppType: "messaging"}, // из whitelist.txt, альт. домен VK
		{Host: "ok.ru",   Weight: 12, AppType: "messaging"},
		{Host: "mail.ru", Weight: 10, AppType: "messaging"},
		{Host: "max.ru",  Weight: 9,  AppType: "messaging"}, // новый гос. мессенджер, из whitelist.txt

		// ── video ─────────────────────────────────────────────────────────────
		// VK Видео обогнало YouTube в РФ по MAU после блокировок.
		{Host: "vkvideo.ru",   Weight: 8, AppType: "video"},
		{Host: "kinopoisk.ru", Weight: 7, AppType: "video"},
		{Host: "rutube.ru",    Weight: 6, AppType: "video"}, // из whitelist.txt

		// ── store ─────────────────────────────────────────────────────────────
		// RuStore — официальный магазин после ухода Google Play.
		// backapi — домен для фоновых обновлений приложений.
		{Host: "rustore.ru",         Weight: 12, AppType: "store"},
		{Host: "backapi.rustore.ru", Weight: 3,  AppType: "store"},

		// ── download ──────────────────────────────────────────────────────────
		// Steam/Epic/GOG и т.п. — многочасовые закачки десятков ГБ. Это НЕ
		// браузинг (объём и длительность сразу выдадут несоответствие, если
		// decoy будет "почитал кommersant.ru 2 минуты"), и фоллбэк на browser
		// тут не годится. RuStore — единственный крупный RU-сервис в пуле, где
		// многочасовая закачка большого объёма (игра, прошивка) — естественное
		// поведение, поэтому используем его decoy и для этой категории тоже.
		{Host: "rustore.ru",         Weight: 10, AppType: "download"},
		{Host: "backapi.rustore.ru", Weight: 3,  AppType: "download"},

		// ── ai ────────────────────────────────────────────────────────────────
		// Алиса и GigaChat — два крупных российских AI в белом списке.
		// GigaChat растёт после интеграции в Сбербанк Онлайн (~50М юзеров).
		{Host: "alice.yandex.ru",  Weight: 6, AppType: "ai"},
		{Host: "gigachat.sber.ru", Weight: 4, AppType: "ai"},

		// ── music ─────────────────────────────────────────────────────────────
		// Яндекс Музыка — #1 в РФ. radio.yandex.ru — фоновое радио.
		{Host: "music.yandex.ru", Weight: 12, AppType: "music"},
		{Host: "radio.yandex.ru", Weight: 4,  AppType: "music"},

		// ── maps ──────────────────────────────────────────────────────────────
		// 2ГИС — обогнал Яндекс.Карты по мобильному трафику в 2024.
		{Host: "2gis.ru",        Weight: 10, AppType: "maps"},
		{Host: "maps.yandex.ru", Weight: 8,  AppType: "maps"},

		// ── cloud ─────────────────────────────────────────────────────────────
		// Яндекс Диск — крупнейшее RU-облако. webdav — для десктопного клиента.
		{Host: "disk.yandex.ru",    Weight: 8, AppType: "cloud"},
		{Host: "webdav.yandex.net", Weight: 3, AppType: "cloud"},

		// ── cdn ───────────────────────────────────────────────────────────────
		// Российские CDN — статические ассеты Яндекса и VK.
		// Трафик высокочастотный и короткий: идеальный "шум" для маскировки.
		{Host: "yastatic.net",           Weight: 15, AppType: "cdn"},
		{Host: "userapi.com",            Weight: 8,  AppType: "cdn"},
		{Host: "avatars.mds.yandex.net", Weight: 6,  AppType: "cdn"},
		{Host: "static.vk.com",         Weight: 5,  AppType: "cdn"},
		{Host: "st.vk.com",             Weight: 4,  AppType: "cdn"},
		{Host: "leonardo.osnova.io",     Weight: 3,  AppType: "cdn"},

		// ── iot  ───────────────────────────────────────────────────────────────
		// Яндекс Интернетометр - единственный сервис для проверки скорости с white-list.
		{Host: "internet.yandex.ru",      Weight: 12, AppType: "iot"},
		{Host: "ipv4-internet.yandex.net", Weight: 10, AppType: "iot"},
		{Host: "ipv6-internet.yandex.net", Weight: 8,  AppType: "iot"},
	},
	counter: &SNICounter{
		counts:       make(map[string][]time.Time),
		maxPerWindow: 30,           // макс. 30 соединения к одному SNI за 60с
		window:       60 * time.Second,
	},
}

func init() {
	for _, e := range defaultPool.entries {
		defaultPool.total += e.Weight
	}
	checkPoolCoverage()
}

// knownAppTypes — все типы трафика, которые реально используются в
// классификаторе (см. AppType-константы в app_classifier.go). Список нужно
// обновлять при добавлении новых AppType — иначе защитная проверка ниже
// просто не увидит новый тип и не предупредит о пробеле в пуле.
var knownAppTypes = []string{
	"browser", "video", "messaging", "iot", "store", "ai", "music",
	"maps", "cloud", "cdn", "download", "browser_core", "api",
}

// intentionalBrowserFallback — типы, у которых СОЗНАТЕЛЬНО нет своих
// decoy-записей: их трафик (короткие фоновые вызовы — api, browser_core)
// поведенчески неотличим от обычного браузинга, поэтому фоллбэк на browser —
// это и есть правильная маскировка, а не "запасной вариант на безрыбье".
// Если тип НЕ в этом списке и не имеет записей в пуле — это баг
// (см. историю: app=api и app=download раньше тихо проваливались в
// случайный фоллбэк по всему пулу и могли получить decoy типа
// ipv4-internet.yandex.net — IoT/speedtest-домен — для коротких API-вызовов).
var intentionalBrowserFallback = map[string]bool{
	"browser_core": true,
	"api":          true,
}

// checkPoolCoverage предупреждает на старте, если для какого-то известного
// AppType нет ни явных записей в пуле, ни осознанного допуска на
// browser-фоллбэк. Не паникует — это диагностика, а не блокировка запуска.
func checkPoolCoverage() {
	covered := make(map[string]bool)
	for _, e := range defaultPool.entries {
		covered[e.AppType] = true
	}
	for _, at := range knownAppTypes {
		if !covered[at] && !intentionalBrowserFallback[at] {
			log.Printf("[SNIPool] WARNING: AppType %q не имеет decoy-записей в пуле и не помечен как intentionalBrowserFallback — трафик уйдёт в случайный фоллбэк по всему пулу", at)
		}
	}
}

// Pick выбирает SNI взвешенно, с учётом лимита соединений.
// До 5 попыток найти незаблокированный SNI, потом fallback на наименее загруженный.
func (p *SNIPool) Pick() string {
	for attempt := 0; attempt < 5; attempt++ {
		r := rand.Intn(p.total)
		cumulative := 0
		for _, e := range p.entries {
			cumulative += e.Weight
			if r < cumulative {
				if p.counter.Allow(e.Host) {
					return e.Host
				}
				break
			}
		}
	}
	return p.leastLoaded(p.entries)
}

// PickForApp выбирает SNI, совместимый с типом трафика.
// Например, для AppVideo берётся SNI из video-записей (vkvideo.ru, kinopoisk.ru),
// чтобы upload/download ratio в TLS-сессии соответствовал паттерну домена.
// Fallback: если для appType нет записей — берём весь пул.
func (p *SNIPool) PickForApp(appType AppType) string {
	candidates := make([]SNIEntry, 0, 4)
	for _, e := range p.entries {
		if e.AppType == string(appType) {
			candidates = append(candidates, e)
		}
	}
	if len(candidates) == 0 {
		// Раньше тут было candidates = p.entries — весь пул вперемешку,
		// с шансом получить decoy совершенно несовместимого поведения
		// (например, ipv4-internet.yandex.net — IoT/speedtest-домен —
		// для коротких API-вызовов app=api). Безопасный дефолт — browser:
		// фоновые/лёгкие запросы неотличимы от обычного браузинга, а вот
		// видео/музыка/спидтест — отличимы, и для них такой фоллбэк сам
		// стал бы демаскирующим сигналом.
		for _, e := range p.entries {
			if e.AppType == "browser" {
				candidates = append(candidates, e)
			}
		}
	}

	total := 0
	for _, e := range candidates {
		total += e.Weight
	}

	for attempt := 0; attempt < 10; attempt++ {
		r := rand.Intn(total)
		cum := 0
		for _, e := range candidates {
			cum += e.Weight
			if r < cum {
				if p.counter.Allow(e.Host) {
					return e.Host
				}
				break
			}
		}
	}
	return p.leastLoaded(candidates)
}

// leastLoaded возвращает SNI с наименьшим количеством недавних соединений.
func (p *SNIPool) leastLoaded(candidates []SNIEntry) string {
	best := candidates[0].Host
	bestCount := math.MaxInt
	for _, e := range candidates {
		if n := p.counter.RecentCount(e.Host); n < bestCount {
			bestCount = n
			best = e.Host
		}
	}
	return best
}

// StickyPool — обёртка над SNIPool с залипанием SNI на сессию
type StickyPool struct {
	pool    *SNIPool
	mu      sync.Mutex
	current map[AppType]stickyEntry
}

type stickyEntry struct {
	sni       string
	expiresAt time.Time
}

func NewStickyPool(pool *SNIPool) *StickyPool {
	return &StickyPool{
		pool:    pool,
		current: make(map[AppType]stickyEntry),
	}
}

func (s *StickyPool) PickForApp(appType AppType) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.current[appType]
	if ok && time.Now().Before(entry.expiresAt) {
		return entry.sni  // возвращаем тот же SNI
	}

	// Выбираем новый SNI и фиксируем на 2-4 минуты
	sni := s.pool.PickForApp(appType)
	duration := 2*time.Minute + time.Duration(rand.Intn(120))*time.Second
	s.current[appType] = stickyEntry{
		sni:       sni,
		expiresAt: time.Now().Add(duration),
	}
	log.Printf("[SNIPool] new sticky sni=%s app=%s ttl=%s", sni, appType, duration.Round(time.Second))
	return sni
}
