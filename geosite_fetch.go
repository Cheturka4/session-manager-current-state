package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// geositeBaseURL — raw-файлы v2fly/domain-list-community. Каждый файл в
// data/ — одна геосайт-категория (компания или тематика), простой текстовый
// формат: "# комментарий", голый домен, "full:exact.domain", "regexp:...",
// "keyword:...", "include:другой_файл", опционально с суффиксом "@attribute"
// (например "@cn", "@ads"). Для нашего SNI-пула нас интересуют только
// литеральные домены (голые строки и full:) — regexp/keyword не годятся
// как конкретное значение SNI.
const geositeBaseURL = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/"

// geositeCategories — категории geosite, которые стоит затянуть под наши
// AppType. Список НЕ проверен полностью на актуальные имена файлов в репо —
// company-файлы вроде tencent/alibaba/openai подтверждены, остальные (netease,
// bilibili, bytedance и т.п.) стоит свериться по дереву репозитория
// (github.com/v2fly/domain-list-community/tree/master/data) перед стартом,
// имя файла может отличаться от ожидаемого.
var geositeCategories = map[string]AppType{
	"tencent":   AppMessaging, // WeChat/QQ и связанная инфраструктура
	"alibaba":   AppStore,
	"bytedance": AppVideo, // TikTok/Douyin — свериться, что файл называется именно так
	"netease":   AppMusic, // NetEase Cloud Music — свериться с именем файла
	"bilibili":  AppVideo,
	"baidu":     AppAI,
	"openai":    AppAI,
	"google":    AppBrowser,
	"apple":     AppBrowser,
	"microsoft": AppCloud,
}

// fetchGeositeCategory тянет один geosite-файл и возвращает только
// литеральные домены (без regexp:/keyword:, без include: — эти строки
// логируются, но не разворачиваются рекурсивно в этой версии).
func fetchGeositeCategory(category string) ([]string, error) {
	url := geositeBaseURL + category
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("geosite fetch %s: %w", category, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("geosite fetch %s: HTTP %d (имя файла в репозитории могло измениться)", category, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var domains []string
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Срезаем @attribute-суффикс (например "domain.com @cn" или "domain.com @ads")
		if idx := strings.Index(line, "@"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}

		switch {
		case strings.HasPrefix(line, "full:"):
			domains = append(domains, strings.TrimPrefix(line, "full:"))
		case strings.HasPrefix(line, "domain:"):
			domains = append(domains, strings.TrimPrefix(line, "domain:"))
		case strings.HasPrefix(line, "regexp:"), strings.HasPrefix(line, "keyword:"):
			// Не литеральный домен — пропускаем, для SNI-пула не годится как есть
			continue
		case strings.HasPrefix(line, "include:"):
			// TODO: при необходимости рекурсивно подтягивать included-файлы —
			// пока просто пропускаем, чтобы не читать чужие category-файлы неявно
			fmt.Printf("[Geosite] %s: include %s пропущен (не разворачиваем рекурсивно)\n", category, strings.TrimPrefix(line, "include:"))
			continue
		default:
			domains = append(domains, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return domains, nil
}

// FetchGeositeCandidates тянет все настроенные категории и раскладывает
// домены по AppType в cloudflareRulesByRegion["CN"] (переиспользуем ту же
// структуру, что и для Cloudflare Radar — источник данных другой, назначение
// то же: категоризированный домен → AppType для китайского SNI-пула).
func FetchGeositeCandidates() (map[string]AppType, error) {
	result := make(map[string]AppType)
	for category, app := range geositeCategories {
		domains, err := fetchGeositeCategory(category)
		if err != nil {
			fmt.Printf("[Geosite] ошибка %s: %v\n", category, err)
			continue
		}
		for _, d := range domains {
			result[d] = app
		}
		fmt.Printf("[Geosite] %s (%v): %d доменов\n", category, app, len(domains))
	}
	return result, nil
}
