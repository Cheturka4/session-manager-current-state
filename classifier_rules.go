package main

// Ручной список — российские и специфичные сервисы
// которых нет в Cloudflare Radar Top 1000
var manualRules = map[string]AppType{
	// Российские видео
	"kinopoisk.ru":    AppVideo,
	"vkvideo.ru":      AppVideo,
	"rutube.ru":       AppVideo,
	"okko.tv":         AppVideo,
	"more.tv":         AppVideo,

	// Российские мессенджеры и соцсети
	"vk.com":          AppMessaging,
	"ok.ru":           AppMessaging,
	"tenchat.ru":      AppMessaging,

	// IoT / умный дом
	"iot.yandex.ru":   AppIoT,
	"hass.io":         AppIoT,
	"quasar.yandex.ru": AppIoT,

	// CDN которые используют российские сервисы
	"yastatic.net":    AppBrowser,
	"vk-cdn.net":      AppMessaging,
}

// Эвристика для полностью неизвестных хостов
func ClassifyByHeuristic(host string, avgPacketSize int, sessionSecs int) AppType {
	// Длинная сессия + большие пакеты → скорее всего видео
	if sessionSecs > 300 && avgPacketSize > 800 {
		return AppVideo
	}
	// Короткие пакеты часто → мессенджер
	if avgPacketSize < 200 {
		return AppMessaging
	}
	return AppBrowser
}

// Обновлённый классификатор: manual → cloudflare → эвристика
func ClassifyHost(host string, avgPacketSize int, sessionSecs int) AppType {
	// 1. Ручной список (высший приоритет)
	if appType, ok := manualRules[host]; ok {
		return appType
	}
	// 2. Cloudflare Radar (загружается при старте)
	if appType, ok := cloudflareRules[host]; ok {
		return appType
	}
	// 3. Keyword matching
	appType := ClassifyByHost(host)
	if appType != AppBrowser {
		return appType
	}
	// 4. Эвристика
	return ClassifyByHeuristic(host, avgPacketSize, sessionSecs)
}

// cloudflareRules заполняется из fetchCloudflareTop1000()
var cloudflareRules = map[string]AppType{}
