package main

import (
	"strings"
	"time"
)

type AppType string

const (
	AppBrowser   AppType = "browser"
	AppVideo     AppType = "video"
	AppMessaging AppType = "messaging"
	AppIoT       AppType = "iot"    // speedtest, погода, умный дом
	AppStore     AppType = "store"
	AppAI        AppType = "ai"
	AppMusic     AppType = "music"
	AppMaps      AppType = "maps"
	AppCloud     AppType = "cloud"
	AppCDN       AppType = "cdn"
	AppAPI       AppType = "api" // лёгкие служебные REST/JSON-вызовы (см. hasAPIPrefix)
	AppDownload  AppType = "download"
	AppBrowserCore AppType = "browser_core" // инфраструктура браузера: sync, update, телеметрия
)

// activityMultiplier — браузер активнее в определённое время суток (МСК).
// DPI, обученный на реальных пользователях, ожидает такой паттерн.
func activityMultiplier() float64 {
	hour := time.Now().In(time.FixedZone("MSK", 3*3600)).Hour()
	switch {
		case hour >= 9 && hour <= 12:
			return 1.2 // утро, активно
		case hour >= 13 && hour <= 14:
			return 0.7 // обед, спад
		case hour >= 18 && hour <= 23:
			return 1.5 // вечер, пик
		case hour >= 0 && hour <= 7:
			return 0.2 // ночь, почти нет активности
		default:
			return 1.0
	}
}

// cdnSubdomainPrefixes — типовые префиксы CDN-поддоменов у ЛЮБОГО сервиса.
// Если хост начинается с одного из этих лейблов, это статика (JS/CSS/картинки/
// сегменты), даже если родительский домен классифицирован как AI/Video/Messaging.
// У статики совсем другой трафик-профиль (короткая сессия, почти 0 upload),
// поэтому проверяем это ДО суффиксного матчинга по домену.
//
// Баг, который это чинит: cdn.openai.com совпадал по суффиксу "openai.com" →
// уходил в AppAI с профилем min5s (как будто это сам чат-запрос), хотя по факту
// это просто статика OpenAI. Теперь cdn.* перехватывается раньше и уходит в AppCDN.
var cdnSubdomainPrefixes = []string{
	"cdn.", "static.", "assets.", "img.", "imgs.", "images.", "media-cdn.",
}

func hasCDNPrefix(host string) bool {
	for _, p := range cdnSubdomainPrefixes {
		if strings.HasPrefix(host, p) {
			return true
		}
	}
	return false
}

// apiPrefixOverrides — api.*-поддомены, которые на самом деле являются
// ОСНОВНЫМ трафиком сервиса, а не вспомогательным REST-вызовом вокруг чего-то
// другого (например, api.mistral.ai — это сам LLM API, а не служебный вызов
// вокруг сайта mistral.ai). Такие домены должны попадать в свою настоящую
// категорию, а не в общий AppAPI.
//
// Проверяется ДО общего hasAPIPrefix(), чтобы не перетереть корректную
// классификацию, которая раньше задавалась через case-блоки ниже (AI,
// BrowserCore). Список должен оставаться синхронизирован с такими записями
// в самих case-блоках — если добавляешь новый api.*-домен туда, проверь,
// не нужно ли его сюда.
var apiPrefixOverrides = map[string]AppType{
	"api.browser.yandex.ru":  AppBrowserCore,
	"api.browser.yandex.com": AppBrowserCore,
	"api.mistral.ai":         AppAI,
	"api.cohere.ai":          AppAI,
}

// apiSubdomainPrefixes — типовой префикс лёгких служебных API-вызовов у
// ЛЮБОГО сервиса. Зеркально hasCDNPrefix(), но для обратного случая: вместо
// статики это REST/JSON-вызовы (статус, профиль, список покупок и т.п.),
// которые НЕ должны наследовать "тяжёлый" профиль родительского домена.
//
// Баг, который это чинит: api.steampowered.com совпадал по суффиксу
// "steampowered.com" → уходил в AppDownload (профиль "до 3 часов, без лимита
// байт", как будто это сама закачка 80GB игры), хотя по факту это лёгкий
// API-вызов (баланс кошелька, список друзей и т.п.). Теперь api.*
// перехватывается раньше (но после apiPrefixOverrides) и уходит в AppAPI.
var apiSubdomainPrefixes = []string{
	"api.",
}

func hasAPIPrefix(host string) bool {
	for _, p := range apiSubdomainPrefixes {
		if strings.HasPrefix(host, p) {
			return true
		}
	}
	return false
}

// ClassifyByHost определяет тип приложения по хосту НАЗНАЧЕНИЯ.
//
// Важно: этот хост — куда идёт трафик пользователя (youtube.com, telegram.org, etc.).
// Он НЕ используется как SNI-маскировка — для этого есть SNIPool.PickForApp().
// ClassifyByHost может содержать любые домены (иностранные, российские) —
// цель: выбрать правильный SessionProfile (upload ratio, volume cap, duration).
//
// Иностранный трафик без явной категории → AppBrowser (download-dominant, норм).
//
// Приоритеты (от специфичного к общему):
//   CDN-префикс (любой домен) → api.*-override → api.*-общий (AppAPI) →
//   CDN (явный список) → Store → AI → Music → Maps → Cloud → Video →
//   Messaging → Browser
func ClassifyByHost(host string) AppType {
	host = strings.ToLower(host)

	// Самый общий и самый приоритетный кейс: поддомен явно CDN-формата
	// (cdn.*, static.*, assets.*...) — независимо от того, что дальше.
	if hasCDNPrefix(host) {
		return AppCDN
	}

	// api.*-поддомены: сначала явные исключения (это на самом деле основной
	// AI/BrowserCore трафик, а не служебный вызов), затем общий перехват
	// в лёгкий профиль AppAPI — ДО того, как суффиксный матч по родительскому
	// домену (например, steampowered.com → AppDownload) успеет сработать ниже.
	if appType, ok := apiPrefixOverrides[host]; ok {
		return appType
	}
	if hasAPIPrefix(host) {
		return AppAPI
	}

	// sfx возвращает true, если host == pattern или оканчивается на "."+pattern.
	// Это точный матчинг: "evk.com" не совпадёт с "vk.com".
	sfx := func(pattern string) bool {
		return host == pattern || strings.HasSuffix(host, "."+pattern)
	}
	any := func(patterns ...string) bool {
		for _, p := range patterns {
			if sfx(p) {
				return true
			}
		}
		return false
	}

	switch {

		// ── CDN ──────────────────────────────────────────────────────────────────
		// Статические ассеты: JS, CSS, картинки. Почти чистый download, короткие сессии.
		// Российские CDN (yastatic, userapi...) + глобальные (Akamai, Fastly, Cloudflare).
		case any(
			// Российские
			"yastatic.net",
			"avatars.mds.yandex.net", "avatars.yandex.net",
			"userapi.com",
			"static.vk.com", "st.vk.com",
			"leonardo.osnova.io",
			"cdn.2gis.ru", "imgs.2gis.com",
			// Глобальные (Cloudflare top-5000)
			"akamaiedge.net", "akamaihd.net", "akamaized.net", "akamaitechnologies.com",
			"cloudflare.com", "cloudflare.net", "cloudflareinsights.com",
			"fastly.net",
			"gstatic.com",
			"jsdelivr.net",
			"unpkg.com",
		):
		return AppCDN

		// ── Download (известные платформы) ──────────────────────────────────────
		// Steam/Epic/GOG/Battle.net/EA/Ubisoft/Riot — стабильные домены, легко
		// классифицировать. ВАЖНО: это покрывает только именованные платформы.
		// Браузерные загрузки с произвольных сайтов и торренты по hostname не
		// отличить от обычного трафика — для них работает отдельный механизм
		// в pipe() (см. socks5_server.go): соединение с низким upload ratio не
		// убивается при достижении MaxBytes, независимо от категории.
		case any(
			// Steam
			"steampowered.com", "steamcontent.com", "steamstatic.com",
			"steamcdn-a.akamaihd.net", "steamusercontent.com",
			// Epic Games
			"epicgames.com", "easyanticheat.net", "fortnite.com",
			// GOG
			"gog.com", "gog-statics.com", "gogalaxy.com",
			// Battle.net / Blizzard
			"battle.net", "blizzard.com", "battlenet.com.cn",
			// EA / Origin
			"ea.com", "origin.com", "easvc.akadns.net",
			// Ubisoft
			"ubisoft.com", "ubi.com", "ubisoftconnect.com",
			// Riot
			"riotgames.com", "leagueoflegends.com", "valorant.com",
		):
		return AppDownload

		// ── Browser Core (инфраструктура браузера, НЕ браузинг) ──────────────────
		// Sync/update/телеметрия самого браузерного приложения. Мелкие, частые,
		// предсказуемые по расписанию запросы — совсем другой профиль, чем
		// "пользователь читает произвольный сайт" (это остаётся в AppBrowser ниже).
		case any(
			// Yandex Browser (подтверждено в whitelist.txt)
			"browser.yandex.ru", "browser.yandex.com",
			"api.browser.yandex.ru", "api.browser.yandex.com",
			"sync.browser.yandex.net",
			// Chrome
			"clients2.google.com", "clients4.google.com", "clients6.google.com",
			"update.googleapis.com", "safebrowsing.googleapis.com",
			// Firefox
			"aus5.mozilla.org", "versioncheck-bg.addons.mozilla.org",
			"content-signature-2.cdn.mozilla.net", "push.services.mozilla.com",
			"normandy.cdn.mozilla.net", "firefox.settings.services.mozilla.com",
			// Brave
			"laptop-updates.brave.com", "redirector.brave.com",
			"variations.brave.com", "components.brave.com",
			// Opera
			"autoupdate.geo.opera.com", "sitecheck2.opera.com",
		):
		return AppBrowserCore

		// Крупные APK/IPA скачивания. Один огромный download, мелкий upload.
		case any(
			// Российские
			"rustore.ru", "backapi.rustore.ru",
			// Глобальные (Cloudflare top-5000)
			"mzstatic.com",       // Apple App Store assets
			"windowsupdate.com",  // Windows Update
			"sourceforge.net",
		):
		return AppStore

		// ── AI ────────────────────────────────────────────────────────────────────
		// Короткий запрос → длинный стриминговый ответ. Частые паузы между сессиями.
		case any(
			// ── Российские ──
			"alice.yandex.ru", "alisa.yandex.ru",           // Яндекс Алиса
			"gigachat.sber.ru", "ngc.sber.ru",               // GigaChat (Сбер)
		"sberdevices.ru",                                // Сбер AI платформа

		// ── Чат-боты и LLM API ──
		"openai.com", "oaiusercontent.com", "chatgpt.com",
		"anthropic.com", "claude.ai",
		"gemini.google.com", "generativelanguage.googleapis.com",
		"mistral.ai", "api.mistral.ai",
		"cohere.com", "api.cohere.ai",
		"groq.com",
		"together.ai", "togetherai.com",
		"fireworks.ai",
		"deepinfra.com",
		"replicate.com",
		"anyscale.com",

		// ── Китайские модели ──
		"deepseek.com",
		"qianwen.aliyun.com", "dashscope.aliyuncs.com", // Qwen (Alibaba)
		"hunyuan.tencent.com",                           // Hunyuan (Tencent)
		"ernie.baidu.com", "aip.baidubce.com",           // ERNIE (Baidu)
		"bigmodel.cn", "open.bigmodel.cn",               // GLM (Zhipu AI)
		"moonshot.cn", "kimi.ai",                        // Kimi (Moonshot)
		"minimax.io", "minimaxi.com",                    // MiniMax

		// ── AI-ассистенты и агрегаторы ──
		"huggingface.co",
		"perplexity.ai",
		"you.com",
		"phind.com",
		"poe.com",
		"character.ai",
		"pi.ai",

		// ── AI для кода ──
		"cursor.sh", "api2.cursor.sh",    // Cursor IDE
		"codeium.com",                    // Codeium
		"github.com", "copilot.github.com",
		"tabnine.com",
		"sourcegraph.com",                // Cody
		"opencode.ai",                    // OpenCode
		"ollama.ai", "ollama.com",        // Ollama
		"lmstudio.ai",                    // LM Studio
		):
		return AppAI

		// ── Music ─────────────────────────────────────────────────────────────────
		// Непрерывный поток: крошечный запрос, огромный ответ. Очень низкий upload ratio.
		case any(
			// Российские
			"music.yandex.ru", "radio.yandex.ru", "strm.yandex.ru",
			// Глобальные (Cloudflare top-5000)
			"spotify.com", "scdn.co", "byspotify.com", "spotifycdn.com",
			"soundcloud.com", "sndcdn.com",
			"deezer.com",
			"tidal.com",
			"pandora.com",
			"shazam.com",
			"bandcamp.com",
			"mixcloud.com",
			"audiomack.com",
		):
		return AppMusic

		// ── Maps ──────────────────────────────────────────────────────────────────
		// Tile-запросы: много мелких GET, ответы — картинки тайлов.
		case any(
			// Российские
			"2gis.ru", "maps.yandex.ru", "api-maps.yandex.ru",
			"core-renderer-tiles.maps.yandex.net",
			// Глобальные (Cloudflare top-5000)
			"mapbox.com",
			"openstreetmap.org",
			"here.com",
			"waze.com",
		):
		return AppMaps

		// ── Cloud ─────────────────────────────────────────────────────────────────
		// Синхронизация: и скачивает и отправляет. Относительно высокий upload ratio.
		case any(
			// Российские
			"disk.yandex.ru", "disk.yandex.net", "webdav.yandex.net",
			"downloader.disk.yandex.ru",
			"cloud.mail.ru",
			// Глобальные (Cloudflare top-5000)
			"dropbox.com", "dropboxusercontent.com",
			"box.com", "box.net",
			"icloud.com",
			"mega.nz",
		):
		return AppCloud

		// ── Video ─────────────────────────────────────────────────────────────────
		// Стриминг: почти чистый download. Длинные сессии (фильм = 1.5ч).
		case any(
			// Российские
			"kinopoisk.ru", "video.yandex.ru",
			"video.vk.com", "clips.vk.com", "vkvideo.ru",
			"vkuseraudio.net", "vkuservideo.net",
			// Глобальные (Cloudflare top-5000)
			"youtube.com", "googlevideo.com", "ytimg.com", "youtu.be",
			"netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com",
			"twitch.tv", "twitchscdn.com", "jtvnw.net", "ext-twitch.tv",
			"tiktok.com", "tiktokcdn.com", "tiktokv.com", "musical.ly",
			"hulu.com", "hulustream.com",
			"disneyplus.com", "dssott.com", "bamgrid.com",
			"max.com", "hbomax.com",
			"vimeo.com", "vimeocdn.com",
			"dailymotion.com", "dmcdn.net",
			"bilibili.com", "bilibili.tv", "bilivideo.com",
			"crunchyroll.com", "crunchyrollcdn.com",
			"peacocktv.com",
			"paramountplus.com",
			"kick.com",
		):
		return AppVideo

		// ── Messaging ─────────────────────────────────────────────────────────────
		// Двунаправленный трафик: текст + медиа. Upload ratio заметно выше браузера.
		case any(
			// Российские
			"vk.me", "mail.ru", "ok.ru",
			// Глобальные (Cloudflare top-5000)
			"telegram.org", "t.me", "telegram.me",
			"discord.com", "discordapp.com",
			"whatsapp.com", "whatsapp.net", "wa.me",
			"signal.org", "whispersystems.org",
			"slack.com", "slack-edge.com",
			"line.me",
			"viber.com",
			"snapchat.com",
			"twitter.com", "x.com", "twimg.com", "t.co",
			"instagram.com",
			"facebook.com", "fbcdn.net", "fb.com", "messenger.com",
		):
		return AppMessaging

		// ── IoT / Speedtest ───────────────────────────────────────────────────────
		// Симметричный трафик (upload ≈ download). Speedtest, погода, умный дом.
		case any(
			// Яндекс Интернетометр
			"internet.yandex.ru",
			"ipv4-internet.yandex.net",
			"ipv6-internet.yandex.net",
			"cdn.yandex.net",        // покрывает cloudcdn-*.cdn.yandex.net
			// Speedtest/Ookla
			"speedtest.net", "fast.com", "speed.cloudflare.com",
			"ooklaserver.net",
			"wsqm.telekom-dienste.de",
			"synlinq.de",
			"webdiscount.net",
			"23m.com",
			"lamasatpro.com",
			"clouvider.net",
			"wemacom.net",
			"twerion.net",
			"cdnst.net",
			"kamatera.com",
			"58243.as",
			"zdbb.net",
			"gurgle.net",
			// Яндекс IoT
			"iot.yandex.ru", "quasar.yandex.ru", "iot.yandex.net",
			"gismeteo.ru", "meteoinfo.ru",
		):
		return AppIoT

		// ── Browser (default) ─────────────────────────────────────────────────────
		// Всё остальное: обычный HTTP/HTTPS браузер. Download-dominant, 8% upload.
		default:
			return AppBrowser
	}
}

// SessionProfile — поведенческие параметры сессии для типа приложения.
type SessionProfile struct {
	SNIAppType  string
	MinDuration int     // минимальная длительность сессии, сек
	MaxDuration int     // максимальная длительность сессии, сек
	PauseMin    int     // минимальная пауза между сессиями, сек
	PauseMax    int     // максимальная пауза между сессиями, сек
	UploadRatio float64 // ожидаемая доля upload от total трафика
	MaxBytes    int64   // максимум байт на сессию (volume cap)
}

var profiles = map[AppType]SessionProfile{
	AppBrowser: {
		SNIAppType:  "browser",
		MinDuration: 120, MaxDuration: 480, // 2–8 мин
		PauseMin: 10, PauseMax: 60,
		UploadRatio: 0.08,             // браузер: GET-запросы мелкие
		MaxBytes:    50 * 1024 * 1024, // 50 MB — страница не качается вечно
	},
	AppVideo: {
		SNIAppType:  "video",
		MinDuration: 360, MaxDuration: 840, // 6–14 мин (буферизация)
		PauseMin: 5, PauseMax: 30,
		UploadRatio: 0.02,              // стриминг: почти чистый download
		MaxBytes:    700 * 1024 * 1024, // 700 MB ≈ 1.5ч HD
	},
	AppMessaging: {
		SNIAppType:  "messaging",
		MinDuration: 180, MaxDuration: 600, // 3–10 мин
		PauseMin: 15, PauseMax: 90,
		UploadRatio: 0.35,              // мессенджер: двунаправленный
		MaxBytes:    100 * 1024 * 1024, // 100 MB
	},
	AppIoT: {
		SNIAppType:  "iot",
		MinDuration: 30, MaxDuration: 120,
		PauseMin: 5, PauseMax: 15,
		UploadRatio: 0.50,            // симметрично
		MaxBytes:    500 * 1024 * 1024, // 500 MB
	},
	AppStore: {
		SNIAppType:  "store",
		MinDuration: 60, MaxDuration: 300, // 1–5 мин (скачивание APK)
		PauseMin: 5, PauseMax: 30,
		UploadRatio: 0.02,              // крупный APK: мелкий запрос → огромный ответ
		MaxBytes:    500 * 1024 * 1024, // 500 MB
	},
	AppAI: {
		SNIAppType:  "ai",
		MinDuration: 5, MaxDuration: 30, // короткие запросы
		PauseMin: 30, PauseMax: 120,
		UploadRatio: 0.15,           // промпт мал, стриминговый ответ велик
		MaxBytes:    5 * 1024 * 1024, // 5 MB
	},
	AppAPI: {
		SNIAppType:  "api",
		MinDuration: 3, MaxDuration: 15, // короткий REST/JSON-вызов, не контент
		PauseMin: 10, PauseMax: 60,
		UploadRatio: 0.10,            // запрос мал, ответ — обычно небольшой JSON
		MaxBytes:    2 * 1024 * 1024, // 2 MB — это служебный вызов, не закачка
	},
	AppMusic: {
		SNIAppType:  "music",
		MinDuration: 600, MaxDuration: 3600, // 10 мин — 1 час
		PauseMin: 1, PauseMax: 5,
		UploadRatio: 0.01,              // поток: запрос крошечный
		MaxBytes:    200 * 1024 * 1024, // 200 MB ≈ 60 мин @ 320kbps
	},
	AppMaps: {
		SNIAppType:  "maps",
		MinDuration: 120, MaxDuration: 600,
		PauseMin: 5, PauseMax: 20,
		UploadRatio: 0.05,            // тайлы: GET → картинка
		MaxBytes:    30 * 1024 * 1024, // 30 MB
	},
	AppCloud: {
		SNIAppType:  "cloud",
		MinDuration: 300, MaxDuration: 1800, // 5–30 мин синхронизации
		PauseMin: 60, PauseMax: 180,
		UploadRatio: 0.30,                // sync: и скачивает и отправляет
		MaxBytes:    1024 * 1024 * 1024, // 1 GB — облачный бэкап
	},
	AppBrowserCore: {
		SNIAppType:  "browser_core",
		MinDuration: 5, MaxDuration: 20, // короткие пинги sync/update
		PauseMin: 180, PauseMax: 900,    // 3–15 мин между проверками — реалистичный sync-интервал
		UploadRatio: 0.20,               // телеметрия и sync шлют заметный upload
		MaxBytes:    2 * 1024 * 1024,    // 2 MB — это не браузинг, это метаданные
	},
	AppDownload: {
		SNIAppType:  "download",
		MinDuration: 600, MaxDuration: 10800, // 10 мин — 3 часа (Steam-игра 80GB)
		PauseMin: 0, PauseMax: 5,
		UploadRatio: 0.01,
		MaxBytes:    0, // 0 = без ограничения, см. GetProfile/pipe()
	},
	AppCDN: {
		SNIAppType:  "cdn",
		MinDuration: 10, MaxDuration: 60,
		PauseMin: 0, PauseMax: 5,
		UploadRatio: 0.02,            // статические ассеты
		MaxBytes:    20 * 1024 * 1024, // 20 MB
	},
}

func GetProfile(app AppType) SessionProfile {
	if p, ok := profiles[app]; ok {
		return p
	}
	return profiles[AppBrowser]
}
