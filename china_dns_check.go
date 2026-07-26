package main

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Проверка "домен не отравлен DNS-цензурой ТСПУ" — ПЕРВИЧНЫЙ, но НЕ
// достаточный фильтр для кандидатов в китайский SNI-пул.
//
// ВАЖНО (см. обсуждение в чате): блок-листы ТСПУ для DNS / HTTP / HTTPS —
// это отдельные, частично пересекающиеся списки, а не один и тот же.
// То, что домен нормально резолвится через китайский DNS, НЕ гарантирует,
// что ТСПУ не режет TLS-соединения с этим доменом в поле SNI. Эта проверка
// отсеивает только явный мусор (домены, для которых ТСПУ уже подделывает
// DNS-ответ) — финальный шорт-лист по каждой категории всё равно стоит
// выборочно проверить вручную (например через публичные "доступен ли сайт
// из Китая" чекеры) перед тем, как зашивать в prod-конфиг.

// chinaDNSResolvers — известные китайские публичные DNS-резолверы.
// 114.114.114.114 (114DNS, Jiangsu) и 180.76.76.76 (Baidu DNS) — оба
// давно используются как раз в felixonmars/dnsmasq-china-list для
// определения "резолвится ли домен по-китайски".
var chinaDNSResolvers = []string{
	"114.114.114.114",
	"180.76.76.76",
}

// referenceResolver — "чистый" резолвер вне зоны действия ТСПУ, с которым
// сравниваем ответ. 1.1.1.1 (Cloudflare), намеренно ОТДЕЛЬНЫЙ от резолвера
// Яндекса, который уже используется в domains_direct.go для прямого обхода
// банков/госуслуг — там другая задача (не палить SNI для чувствительного
// трафика), здесь просто нужен незаражённый ответ для сравнения.
const referenceResolver = "1.1.1.1"

// knownForgedIPs — ПРИМЕР известных поддельных IP, которые ТСПУ подставляет
// в отравленные DNS-ответы (из открытых измерительных исследований, напр.
// gfw.report/GFWatch). Список короткий и НЕ претендует на полноту/актуальность —
// перед реальным использованием стоит подтянуть текущий список с gfwatch.org
// (если датасет всё ещё публикуется) вместо жёсткого хардкода нескольких штук.
var knownForgedIPs = map[string]bool{
	// TODO: заменить/дополнить актуальным дампом с gfwatch.org или
	// gfw.report, если их публичный датасет всё ещё доступен и
	// обновляется — сверить перед использованием в проде.
}

// dnsQueryVia отправляет UDP DNS A-запрос на конкретный резолвер и
// парсит ответ. Переиспользует buildDNSQuery/parseDNSAnswerIPs из
// domains_direct.go — тот же wire-формат, тот же парсер.
func dnsQueryVia(ctx context.Context, resolverIP, host string) ([]net.IP, error) {
	q := buildDNSQuery(host)

	conn, err := net.Dial("udp", net.JoinHostPort(resolverIP, "53"))
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", resolverIP, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(4 * time.Second))
	}

	if _, err := conn.Write(q); err != nil {
		return nil, fmt.Errorf("write to %s: %w", resolverIP, err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		// Таймаут/нет ответа — само по себе подозрительно (многие
		// поддельные ответы ТСПУ вообще не приходят вовремя, либо
		// резолвер молчит на "неправильный" домен), но также может
		// быть просто сетевой проблемой — не считаем это доказательством
		// цензуры, только сигналом для доп. проверки.
		return nil, fmt.Errorf("no response from %s: %w", resolverIP, err)
	}

	return parseDNSAnswerIPs(buf[:n]), nil
}

// ChinaDNSCheckResult — результат сверки одного домена.
type ChinaDNSCheckResult struct {
	Domain          string
	ReferenceIPs    []net.IP
	ChinaIPs        map[string][]net.IP // резолвер → IPs
	Suspicious      bool
	SuspiciousWhy   string
}

// CheckDomainForChina сверяет резолвинг домена через китайские резолверы
// с "чистым" резолвером. Возвращает Suspicious=true, если есть основания
// подозревать DNS-цензуру — НЕ финальный вердикт "заблокирован/не заблокирован",
// см. предупреждение в начале файла про раздельные DNS/HTTP/HTTPS блок-листы.
func CheckDomainForChina(ctx context.Context, domain string) ChinaDNSCheckResult {
	res := ChinaDNSCheckResult{
		Domain:   domain,
		ChinaIPs: make(map[string][]net.IP),
	}

	refIPs, err := dnsQueryVia(ctx, referenceResolver, domain)
	if err != nil {
		res.Suspicious = true
		res.SuspiciousWhy = fmt.Sprintf("reference resolver failed: %v", err)
		return res
	}
	res.ReferenceIPs = refIPs

	for _, resolver := range chinaDNSResolvers {
		ips, err := dnsQueryVia(ctx, resolver, domain)
		if err != nil {
			// Нет ответа от китайского резолвера — не обязательно цензура
			// (резолвер мог просто не ответить публичному внешнему клиенту),
			// но помечаем для ручной проверки.
			res.Suspicious = true
			res.SuspiciousWhy = fmt.Sprintf("no response from %s (needs manual check): %v", resolver, err)
			continue
		}
		res.ChinaIPs[resolver] = ips

		for _, ip := range ips {
			if knownForgedIPs[ip.String()] {
				res.Suspicious = true
				res.SuspiciousWhy = fmt.Sprintf("resolver %s returned known-forged IP %s", resolver, ip.String())
			}
		}
	}

	return res
}

// FilterCandidatesForChina прогоняет список доменов-кандидатов (например,
// пересечение Radar location=CN top-100 и felixonmars accelerated-domains)
// и возвращает только те, что прошли базовую DNS-проверку. Отфильтрованные
// (suspicious) домены логируются для ручного разбора, а не молча
// выбрасываются — среди них могут быть ложные срабатывания (сетевые сбои,
// геолокационная маршрутизация CDN), а не реальная цензура.
func FilterCandidatesForChina(domains []string) (clean []string, suspicious []ChinaDNSCheckResult) {
	for _, d := range domains {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		res := CheckDomainForChina(ctx, d)
		cancel()

		if res.Suspicious {
			suspicious = append(suspicious, res)
			fmt.Printf("[ChinaDNSCheck] SUSPICIOUS %s: %s\n", d, res.SuspiciousWhy)
			continue
		}
		clean = append(clean, d)
	}
	return clean, suspicious
}
