package trafficstats

import (
	_ "embed" // 用于嵌入 HTML 模板
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// dashboardHTML 嵌入了外部的 HTML 模板文件内容。
//
//go:embed template.html
var dashboardHTML string

// parsedTemplate 用于缓存解析后的 HTML 模板。
var parsedTemplate *template.Template

func init() {
	caddy.RegisterModule(Dashboard{})
	httpcaddyfile.RegisterHandlerDirective("traffic_dashboard", parseCaddyfile)

	// 注册模板函数，允许在 HTML 模板中进行 JSON 序列化
	tmpl := template.New("dashboard").Funcs(template.FuncMap{
		"json": func(v interface{}) template.JS {
			a, _ := json.Marshal(v)
			return template.JS(a)
		},
	})

	// 解析模板
	var err error
	parsedTemplate, err = tmpl.Parse(dashboardHTML)
	if err != nil {
		panic("failed to parse embedded dashboard template: " + err.Error())
	}
}

// Dashboard 实现了一个 HTTP 处理器，用于聚合 metrics 并展示流量统计页面。
type Dashboard struct {
	MetricsURL string `json:"metrics_url,omitempty"`
	logger     *zap.Logger
}

// CaddyModule 返回 Caddy 模块信息。
func (Dashboard) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.traffic_dashboard",
		New: func() caddy.Module { return new(Dashboard) },
	}
}

// Provision 初始化模块。
func (d *Dashboard) Provision(ctx caddy.Context) error {
	d.logger = ctx.Logger(d)
	if d.MetricsURL == "" {
		d.MetricsURL = "http://localhost:2019/metrics"
	}
	return nil
}

// ServeHTTP 实现了 caddyhttp.MiddlewareHandler 接口。
func (d Dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	stats, err := d.fetchAndParseStats()
	if err != nil {
		// 记录错误，但返回空数据以保证页面能渲染
		d.logger.Error("failed to gather stats", zap.Error(err))
		if stats == nil {
			stats = &StatsData{
				Protocols: make(map[string]int),
				Codes:     make(map[string]int),
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 执行模板
	return parsedTemplate.Execute(w, stats)
}

// UnmarshalCaddyfile 解析 Caddyfile 配置。
func (d *Dashboard) UnmarshalCaddyfile(dDisp *caddyfile.Dispenser) error {
	for dDisp.Next() {
		for dDisp.NextBlock(0) {
			switch dDisp.Val() {
			case "metrics_url":
				if !dDisp.NextArg() {
					return dDisp.ArgErr()
				}
				d.MetricsURL = dDisp.Val()
			default:
				return dDisp.Errf("unrecognized subdirective: %s", dDisp.Val())
			}
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var d Dashboard
	err := d.UnmarshalCaddyfile(h.Dispenser)
	return d, err
}

// --- 数据处理逻辑 ---

type StatsData struct {
	TotalRequests int            `json:"TotalRequests"`
	Protocols     map[string]int `json:"Protocols"`
	Codes         map[string]int `json:"Codes"`
}

func (d *Dashboard) fetchAndParseStats() (*StatsData, error) {
	resp, err := http.Get(d.MetricsURL)
	if err != nil {
		return nil, fmt.Errorf("metrics request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metrics returned status: %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read body: %w", err)
	}

	return parseMetrics(string(bodyBytes)), nil
}

func parseMetrics(body string) *StatsData {
	stats := &StatsData{
		Protocols: make(map[string]int),
		Codes:     make(map[string]int),
	}

	lines := strings.Split(body, "\n")
	for _, line := range lines {
		processMetricLine(line, stats)
	}
	return stats
}

func processMetricLine(line string, stats *StatsData) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}

	if strings.Contains(line, "caddy_http_requests_total") {
		count := extractCount(line)
		stats.TotalRequests += count
		if proto := extractLabelValue(line, "proto"); proto != "" {
			stats.Protocols[proto] += count
		}
		return
	}

	if strings.Contains(line, "caddy_http_response_duration_seconds_count") {
		if code := extractLabelValue(line, "code"); code != "" {
			count := extractCount(line)
			stats.Codes[code] += count
		}
		return
	}
}

func extractLabelValue(line, label string) string {
	searchKey := label + "=\""
	startIdx := strings.Index(line, searchKey)
	if startIdx == -1 {
		return ""
	}
	startIdx += len(searchKey)
	endIdx := strings.Index(line[startIdx:], "\"")
	if endIdx == -1 {
		return ""
	}
	return line[startIdx : startIdx+endIdx]
}

func extractCount(line string) int {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return 0
	}
	var f float64
	_, err := fmt.Sscanf(parts[len(parts)-1], "%f", &f)
	if err != nil {
		return 0
	}
	return int(f)
}
