package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type radarDomain struct {
	Rank       int    `json:"rank"`
	Domain     string `json:"domain"`
	Category   string `json:"category"`
}

// Загружаем Cloudflare Radar Top 1000 и классифицируем
func fetchCloudflareTop1000() error {
	url := "https://radar.cloudflare.com/charts/LargerTopDomainsTable/attachment?id=968&top=1000"

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("cloudflare fetch error: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var domains []radarDomain
	if err := json.Unmarshal(body, &domains); err != nil {
		// Fallback: парсим как CSV
		return parseCloudflareCSV(string(body))
	}

	for _, d := range domains {
		cloudflareRules[d.Domain] = classifyByCategory(d.Category)
	}
	fmt.Printf("[Cloudflare] Загружено %d доменов\n", len(cloudflareRules))
	return nil
}

func parseCloudflareCSV(data string) error {
	lines := strings.Split(data, "\n")
	for _, line := range lines[1:] { // пропускаем заголовок
		parts := strings.Split(line, ",")
		if len(parts) >= 2 {
			domain := strings.TrimSpace(parts[1])
			cloudflareRules[domain] = AppBrowser // базовая классификация
		}
	}
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
	default:
		return AppBrowser
	}
}

// Запускаем обновление раз в неделю
func StartCloudflareUpdater() {
	go func() {
		if err := fetchCloudflareTop1000(); err != nil {
			fmt.Printf("[Cloudflare] Ошибка загрузки: %v (используем встроенный список)\n", err)
		}
		ticker := time.NewTicker(7 * 24 * time.Hour)
		for range ticker.C {
			fetchCloudflareTop1000()
		}
	}()
}
