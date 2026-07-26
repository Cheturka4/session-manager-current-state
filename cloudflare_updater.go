package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)


// cloudflareRulesByRegion — то же самое, но с разбивкой по стране (location code,
// ISO 3166-1 alpha-2: "RU", "CN", ...). Нужно для per-region SNI-пресетов
// (см. roadmap: manifest.json + regions/*.json) — домен может быть в топ-100
// для России, но совсем не быть релевантным для Китая, и наоборот.
var cloudflareRulesByRegion = make(map[string]map[string]AppType)

// radarDomain — один домен из ответа /radar/ranking/top.
// Radar отдаёт категорию сразу в этом же вызове (поле categories) —
// отдельный запрос на домен (/radar/ranking/domain/{domain}) не нужен.
type radarDomain struct {
	Domain string `json:"domain"`
	Rank   int    `json:"rank"`
	Categories []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"categories"`
}

type radarTopResponse struct {
	Result struct {
		Top0 []radarDomain `json:"top_0"`
	} `json:"result"`
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

// radarAPIToken читается из окружения — токен НЕ хардкодим в исходники
// (см. чат: токен уже светился в скриншоте терминала один раз — ротировать
// его в дашборде и больше никогда не вставлять в код/конфиги в открытом виде).
func radarAPIToken() string {
	return os.Getenv("CF_RADAR_API_TOKEN")
}

// fetchCloudflareTop — тянет топ-100 доменов Radar для одного региона (location,
// ISO alpha-2 код страны, например "RU" или "CN") и раскладывает их по категориям
// в cloudflareRulesByRegion[location] + дублирует в глобальный cloudflareRules.
//
// ОГРАНИЧЕНИЕ (подтверждено ранее): Cloudflare отдаёт упорядоченный ranking
// только для топ-100 доменов на регион/глобально. Для большего объёма есть
// только неупорядоченные bucket-датасеты (top 200k/500k/1M) без per-domain
// категорий в удобном виде — для наших целей (SNI-пул по категориям) топ-100
// достаточно, брать глубже не имеет смысла без доп. обогащения.
func fetchCloudflareTop(location string) error {
	token := radarAPIToken()
	if token == "" {
		return fmt.Errorf("CF_RADAR_API_TOKEN not set")
	}

	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/radar/ranking/top?location=%s&limit=100", location)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("radar fetch error (location=%s): %w", location, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var parsed radarTopResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("radar parse error (location=%s): %w", location, err)
	}
	if !parsed.Success {
		if len(parsed.Errors) > 0 {
			return fmt.Errorf("radar api error (location=%s): %s", location, parsed.Errors[0].Message)
		}
		return fmt.Errorf("radar api error (location=%s): unknown", location)
	}

	regionRules := make(map[string]AppType, len(parsed.Result.Top0))
	for _, d := range parsed.Result.Top0 {
		app := AppBrowser // дефолт, если Radar не прислал категорию
		if len(d.Categories) > 0 {
			app = classifyByCategory(d.Categories[0].Name)
		}
		regionRules[d.Domain] = app
		cloudflareRules[d.Domain] = app // глобальный fallback, без региональной привязки
	}
	cloudflareRulesByRegion[location] = regionRules

	fmt.Printf("[Cloudflare] location=%s: загружено %d доменов\n", location, len(regionRules))
	return nil
}

func classifyByCategory(category string) AppType {
	category = strings.ToLower(category)
	switch {
	case strings.Contains(category, "video"),
		strings.Contains(category, "streaming"):
		return AppVideo
	case strings.Contains(category, "messaging"),
		strings.Contains(category, "social"):
		return AppMessaging
	case strings.Contains(category, "iot"),
		strings.Contains(category, "smart"):
		return AppIoT
	case strings.Contains(category, "shopping"),
		strings.Contains(category, "e-commerce"),
		strings.Contains(category, "retail"):
		return AppStore
	case strings.Contains(category, "search engine"),
		strings.Contains(category, "artificial intelligence"):
		return AppAI
	case strings.Contains(category, "music"),
		strings.Contains(category, "audio"):
		return AppMusic
	case strings.Contains(category, "maps"),
		strings.Contains(category, "navigation"):
		return AppMaps
	case strings.Contains(category, "cloud"),
		strings.Contains(category, "storage"):
		return AppCloud
	case strings.Contains(category, "content servers"),
		strings.Contains(category, "cdn"):
		return AppCDN
	default:
		return AppBrowser
	}
}

// regionsToTrack — регионы, для которых нужны отдельные SNI-пресеты
// (см. roadmap: Russia/China presets, "in main"). Добавлять сюда новые
// ISO alpha-2 коды по мере расширения — сам fetchCloudflareTop региона
// не знает и ничего специфичного для России/Китая не хардкодит.
var regionsToTrack = []string{"RU", "CN"}

// StartCloudflareUpdater запускает первичную загрузку + еженедельное обновление
// по всем отслеживаемым регионам.
func StartCloudflareUpdater() {
	go func() {
		for _, loc := range regionsToTrack {
			if err := fetchCloudflareTop(loc); err != nil {
				fmt.Printf("[Cloudflare] Ошибка загрузки (location=%s): %v (используем встроенный список)\n", loc, err)
			}
		}
		ticker := time.NewTicker(7 * 24 * time.Hour)
		for range ticker.C {
			for _, loc := range regionsToTrack {
				if err := fetchCloudflareTop(loc); err != nil {
					fmt.Printf("[Cloudflare] Ошибка обновления (location=%s): %v\n", loc, err)
				}
			}
		}
	}()
}
