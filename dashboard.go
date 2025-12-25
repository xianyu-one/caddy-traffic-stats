package trafficstats

import (
	_ "embed" // 用于嵌入 HTML 模板
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

	// 初始化解析模板，若失败则 panic，因为这是模块运行的必要条件。
	var err error
	parsedTemplate, err = template.New("dashboard").Parse(dashboardHTML)
	if err != nil {
		panic("failed to parse embedded dashboard template: " + err.Error())
	}
}

// Dashboard 实现了一个 HTTP 处理器，用于聚合 metrics 并展示流量统计页面。
//
// 该模块通过请求 Caddy 的 Prometheus Metrics 端点来获取数据。
type Dashboard struct {
	// MetricsURL 是 Prometheus metrics 数据的获取地址。
	// 默认为 http://localhost:2019/metrics。
	MetricsURL string `json:"metrics_url,omitempty"`

	logger *zap.Logger
}

// CaddyModule 返回 Caddy 模块信息。
func (Dashboard) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.traffic_dashboard",
		New: func() caddy.Module { return new(Dashboard) },
	}
}

// Provision 初始化模块。
//
// 该方法会在模块加载时被调用，用于设置默认值和准备 logger。
func (d *Dashboard) Provision(ctx caddy.Context) error {
	d.logger = ctx.Logger(d)

	// 设置默认 Metrics 地址
	if d.MetricsURL == "" {
		d.MetricsURL = "http://localhost:2019/metrics"
	}
	return nil
}

// ServeHTTP 实现了 caddyhttp.MiddlewareHandler 接口。
//
// 它负责获取统计数据并渲染 HTML 响应。
func (d Dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	stats, err := d.fetchAndParseStats()
	if err != nil {
		// 记录错误但尝试继续渲染（可能会显示空数据），避免直接返回 500 导致页面完全不可用。
		d.logger.Error("failed to gather stats", zap.Error(err))
		if stats == nil {
			stats = &StatsData{
				Protocols: make(map[string]int),
				Codes:     make(map[string]int),
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	return parsedTemplate.Execute(w, stats)
}

// UnmarshalCaddyfile 解析 Caddyfile 配置。
//
// 语法示例:
//
//	traffic_dashboard {
//	    metrics_url http://localhost:2019/metrics
//	}
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

// parseCaddyfile 是注册给 Caddy 的辅助函数，用于从 Token 生成 Handler。
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var d Dashboard
	err := d.UnmarshalCaddyfile(h.Dispenser)
	return d, err
}

// --- 数据处理逻辑 ---

// StatsData 定义了传递给前端模板的数据结构。
type StatsData struct {
	TotalRequests int
	Protocols     map[string]int
	Codes         map[string]int
}

// fetchAndParseStats 执行 HTTP 请求并解析响应数据。
func (d *Dashboard) fetchAndParseStats() (*StatsData, error) {
	resp, err := http.Get(d.MetricsURL)
	if err != nil {
		return nil, fmt.Errorf("request to metrics url failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code from metrics: %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return parseMetrics(string(bodyBytes)), nil
}

// parseMetrics 解析 Prometheus 格式的文本数据。
//
// 该函数只负责纯文本解析，不涉及网络 I/O，便于测试和维护。
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

// processMetricLine 处理单行 metric 数据并更新 stats 对象。
//
// 遵循单一职责原则，每行只处理特定的 metric key。
func processMetricLine(line string, stats *StatsData) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return
	}

	// 处理 HTTP 请求总量及协议分布
	// 示例: caddy_http_requests_total{handler="reverse_proxy",server="srv0",proto="HTTP/2.0"} 123
	if strings.Contains(line, "caddy_http_requests_total") {
		count := extractCount(line)

		// 累加总请求数
		stats.TotalRequests += count

		// 提取协议类型
		if proto := extractLabelValue(line, "proto"); proto != "" {
			stats.Protocols[proto] += count
		}
		return
	}

	// 处理 HTTP 响应状态码
	// 示例: caddy_http_response_duration_seconds_count{code="200",handler="subroute",...} 50
	if strings.Contains(line, "caddy_http_response_duration_seconds_count") {
		// 注意：duration_seconds_count 通常表示特定 bucket 或总次数，
		// 这里我们利用 count 后缀的指标来统计各状态码的出现次数。
		if code := extractLabelValue(line, "code"); code != "" {
			count := extractCount(line)
			stats.Codes[code] += count
		}
		return
	}
}

// extractLabelValue 从 Prometheus 标签字符串中提取特定标签的值。
//
// 示例输入: 'key="value",other="123"'
// 示例标签: "key"
// 返回: "value"
func extractLabelValue(line, label string) string {
	// 构造搜索键，例如 'proto="'
	searchKey := label + "=\""
	startIdx := strings.Index(line, searchKey)
	if startIdx == -1 {
		return ""
	}

	// 移动指针到值开始处
	startIdx += len(searchKey)

	// 查找闭合引号
	endIdx := strings.Index(line[startIdx:], "\"")
	if endIdx == -1 {
		return ""
	}

	return line[startIdx : startIdx+endIdx]
}

// extractCount 从 metric 行末尾提取数值。
//
// 假设行格式为: metric_key{labels} value
func extractCount(line string) int {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return 0
	}

	// 最后一个字段通常是数值
	lastPart := parts[len(parts)-1]

	var f float64
	// 使用 Sscanf 处理可能的浮点数或科学计数法
	_, err := fmt.Sscanf(lastPart, "%f", &f)
	if err != nil {
		return 0
	}
	return int(f)
}
