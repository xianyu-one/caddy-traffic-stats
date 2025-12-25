package trafficstats

import (
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

//go:embed template.html
var dashboardHTML string

var parsedTemplate *template.Template

// --- 全局变量与初始化 ---

var (
	// globalStats 存储全局聚合统计数据
	globalStats = newStatsData()
	globalMu    sync.RWMutex
	// globalMaxEntries 全局 Map 最大条目数 (防内存泄漏)
	globalMaxEntries = 100000
)

func init() {
	caddy.RegisterModule(Dashboard{})
	httpcaddyfile.RegisterHandlerDirective("traffic_dashboard", parseCaddyfile)
	// 注册执行顺序：默认在 reverse_proxy 之前
	httpcaddyfile.RegisterDirectiveOrder("traffic_dashboard", httpcaddyfile.Before, "reverse_proxy")

	initTemplate()
}

// initTemplate 解析内嵌 HTML 模板
func initTemplate() {
	tmpl := template.New("dashboard").Funcs(template.FuncMap{
		// json 序列化函数，用于在模板中注入数据
		"json": func(v interface{}) template.JS {
			a, _ := json.Marshal(v)
			return template.JS(a)
		},
		// title 首字母大写函数
		"title": func(s string) string {
			if len(s) == 0 {
				return ""
			}
			return strings.ToUpper(s[:1]) + s[1:]
		},
	})

	var err error
	parsedTemplate, err = tmpl.Parse(dashboardHTML)
	if err != nil {
		panic("failed to parse embedded dashboard template: " + err.Error())
	}
}

// --- 数据结构定义 ---

// StatsData 核心统计数据结构
type StatsData struct {
	TotalRequests   int            `json:"TotalRequests"`
	TotalWebSockets int            `json:"TotalWebSockets"` // WebSocket 握手成功计数
	Protocols       map[string]int `json:"Protocols"`
	Codes           map[string]int `json:"Codes"`
	TLSVersions     map[string]int `json:"TLSVersions"`
	Transports      map[string]int `json:"Transports"`
	IPVersions      map[string]int `json:"IPVersions"`
}

// newStatsData 创建并初始化 StatsData
func newStatsData() *StatsData {
	return &StatsData{
		Protocols:   make(map[string]int),
		Codes:       make(map[string]int),
		TLSVersions: make(map[string]int),
		Transports:  make(map[string]int),
		IPVersions:  make(map[string]int), // 初始化新 Map
	}
}

// Dashboard Caddy 模块结构体
type Dashboard struct {
	// Path 看板访问路径 (默认 /traffic)
	Path string `json:"path,omitempty"`
	// Scope 统计范围: "global" 或 "instance"
	Scope string `json:"scope,omitempty"`
	// MaxMemoryMB 内存限制 (MB)
	MaxMemoryMB int `json:"max_memory_mb,omitempty"`
	// EnableServe 是否开启 Web 服务和 API
	EnableServe bool `json:"enable_serve,omitempty"`
	// DisableCollect 是否禁用当前站点的统计
	DisableCollect bool `json:"disable_collect,omitempty"`

	logger        *zap.Logger
	instanceStats *StatsData
	instanceMu    sync.RWMutex
	maxEntries    int // 运行时计算的 Map 限制
}

// CaddyModule 实现 Caddy 模块接口
func (Dashboard) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.traffic_dashboard",
		New: func() caddy.Module { return new(Dashboard) },
	}
}

// Provision 模块初始化
func (d *Dashboard) Provision(ctx caddy.Context) error {
	d.logger = ctx.Logger(d)

	d.provisionDefaults()
	d.provisionLimits()
	d.instanceStats = newStatsData()

	return nil
}

// provisionDefaults 设置默认配置
func (d *Dashboard) provisionDefaults() {
	if d.Path == "" {
		d.Path = "/traffic"
	}
	// 移除 Path 末尾的斜杠，统一处理
	d.Path = strings.TrimRight(d.Path, "/")

	if d.Scope == "" {
		d.Scope = "instance"
	}
	if d.MaxMemoryMB <= 0 {
		d.MaxMemoryMB = 64
	}
}

// provisionLimits 计算内存与条目限制
func (d *Dashboard) provisionLimits() {
	// 估算每个条目占用 256 字节
	d.maxEntries = (d.MaxMemoryMB * 1024 * 1024) / 256
	if d.maxEntries < 1000 {
		d.maxEntries = 1000
	}
}

// ServeHTTP 请求处理主入口
func (d *Dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// 1. 处理服务请求 (Dashboard 或 API)
	if d.EnableServe {
		if strings.HasPrefix(r.URL.Path, d.Path) {
			// 精确匹配 Dashboard 路径
			if r.URL.Path == d.Path || r.URL.Path == d.Path+"/" {
				return d.serveDashboard(w)
			}
			// 匹配 API 路径 (e.g. /traffic/api)
			if r.URL.Path == d.Path+"/api" {
				return d.serveAPI(w)
			}
		}
	}

	// 2. 检查是否跳过采集
	if d.DisableCollect {
		return next.ServeHTTP(w, r)
	}

	// 3. 执行采集并继续
	return d.collectAndServe(w, r, next)
}

// collectAndServe 采集逻辑包装
func (d *Dashboard) collectAndServe(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// 记录请求阶段信息
	d.recordRequestInfo(r)

	// 判断是否为 WebSocket 升级请求 (不区分大小写)
	isWSAttempt := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")

	rec := caddyhttp.NewResponseRecorder(w, nil, nil)
	err := next.ServeHTTP(rec, r)

	// 记录响应阶段信息，并根据响应码判断 WebSocket 是否建立成功
	d.recordResponseInfo(rec, isWSAttempt)

	return err
}

// --- 数据采集逻辑 ---

// recordRequestInfo 记录请求阶段信息 (Protocol, TLS, Transport, IPVersion)
func (d *Dashboard) recordRequestInfo(r *http.Request) {
	// 1. 协议版本
	proto := r.Proto
	if proto == "" {
		proto = "Unknown"
	}

	// 2. TLS 版本
	tlsVer := resolveTLSVersion(r.TLS)

	// 3. 传输层协议 (TCP/QUIC)
	transport := resolveTransport(proto)

	// 4. IP 版本 (新增)
	ipVer := resolveIPVersion(r.RemoteAddr)

	// 批量更新
	d.batchUpdateStats(func(s *StatsData, limit int) {
		s.TotalRequests++
		safeIncrement(s.Protocols, proto, limit)
		safeIncrement(s.TLSVersions, tlsVer, limit)
		safeIncrement(s.Transports, transport, limit)
		safeIncrement(s.IPVersions, ipVer, limit)
	})
}

// recordResponseInfo 记录响应阶段信息 (Status Code, WebSocket)
func (d *Dashboard) recordResponseInfo(rec caddyhttp.ResponseRecorder, isWSAttempt bool) {
	code := fmt.Sprintf("%d", rec.Status())

	// 只有当请求头包含 Upgrade: websocket 且响应码为 101 时，才视为成功的 WebSocket 连接
	isWSSuccess := isWSAttempt && rec.Status() == 101

	d.batchUpdateStats(func(s *StatsData, limit int) {
		safeIncrement(s.Codes, code, limit)
		if isWSSuccess {
			s.TotalWebSockets++
		}
	})
}

// batchUpdateStats 辅助函数：同时更新全局和实例数据
func (d *Dashboard) batchUpdateStats(updateFn func(*StatsData, int)) {
	// 更新全局
	globalMu.Lock()
	updateFn(globalStats, globalMaxEntries)
	globalMu.Unlock()

	// 更新实例
	d.instanceMu.Lock()
	updateFn(d.instanceStats, d.maxEntries)
	d.instanceMu.Unlock()
}

// safeIncrement Map 安全自增
func safeIncrement(m map[string]int, key string, limit int) {
	if len(m) < limit || m[key] > 0 {
		m[key]++
	}
}

// resolveTLSVersion 解析 TLS 版本
func resolveTLSVersion(state *tls.ConnectionState) string {
	if state == nil {
		return "No TLS"
	}
	switch state.Version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown TLS"
	}
}

// resolveTransport 解析传输层协议
func resolveTransport(proto string) string {
	// HTTP/3 基于 QUIC
	if strings.HasPrefix(proto, "HTTP/3") {
		return "QUIC"
	}
	// HTTP/1.x 和 HTTP/2 通常基于 TCP (h2c 也是 TCP)
	if strings.HasPrefix(proto, "HTTP/1") || strings.HasPrefix(proto, "HTTP/2") {
		return "TCP"
	}
	return "Other"
}

// resolveIPVersion 解析客户端 IP 是 IPv4 还是 IPv6。
// 它处理 net.SplitHostPort 可能出现的错误，并提供默认值。
func resolveIPVersion(remoteAddr string) string {
	// 移除端口号
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		// 如果无法分割（例如没有端口号，或者被 trusted_proxies 重写过），
		// 直接尝试解析整个字符串
		host = remoteAddr
	}

	// 1. 去除首尾空白 (防止 Caddyfile 配置错误引入空格)
	host = strings.TrimSpace(host)

	// 2. 移除可能的方括号（IPv6 格式 [::1]）
	host = strings.Trim(host, "[]")

	// 3. 处理 Zone ID (例如 fe80::1%eth0)
	// net.ParseIP 不支持 Zone ID，必须去除 % 及其后缀
	if idx := strings.LastIndex(host, "%"); idx != -1 {
		host = host[:idx]
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return "Unknown IP"
	}

	if ip.To4() != nil {
		return "IPv4"
	}
	return "IPv6"
}

// --- 服务响应逻辑 ---

// serveDashboard 渲染 HTML 页面
func (d *Dashboard) serveDashboard(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	snapshot := d.getSnapshot()

	data := struct {
		Scope string
		Stats *StatsData
	}{
		Scope: d.Scope,
		Stats: snapshot,
	}

	return parsedTemplate.Execute(w, data)
}

// serveAPI 返回 JSON 数据 (RESTful)
func (d *Dashboard) serveAPI(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	snapshot := d.getSnapshot()

	enc := json.NewEncoder(w)
	return enc.Encode(snapshot)
}

// getSnapshot 根据 Scope 获取对应的数据快照
func (d *Dashboard) getSnapshot() *StatsData {
	if d.Scope == "global" {
		globalMu.RLock()
		defer globalMu.RUnlock()
		return cloneStats(globalStats)
	}

	d.instanceMu.RLock()
	defer d.instanceMu.RUnlock()
	return cloneStats(d.instanceStats)
}

// cloneStats 深拷贝 StatsData
func cloneStats(src *StatsData) *StatsData {
	dst := newStatsData()
	dst.TotalRequests = src.TotalRequests
	dst.TotalWebSockets = src.TotalWebSockets

	copyMap(dst.Protocols, src.Protocols)
	copyMap(dst.Codes, src.Codes)
	copyMap(dst.TLSVersions, src.TLSVersions)
	copyMap(dst.Transports, src.Transports)
	copyMap(dst.IPVersions, src.IPVersions)

	return dst
}

// copyMap 辅助 Map 拷贝
func copyMap(dst, src map[string]int) {
	for k, v := range src {
		dst[k] = v
	}
}

// --- 配置解析 ---

// UnmarshalCaddyfile 解析 Caddyfile
func (d *Dashboard) UnmarshalCaddyfile(dDisp *caddyfile.Dispenser) error {
	for dDisp.Next() {
		for dDisp.NextBlock(0) {
			directive := dDisp.Val()
			switch directive {
			case "path":
				if !dDisp.NextArg() {
					return dDisp.ArgErr()
				}
				d.Path = dDisp.Val()
			case "scope":
				if !dDisp.NextArg() {
					return dDisp.ArgErr()
				}
				val := dDisp.Val()
				if val != "global" && val != "instance" {
					return dDisp.Errf("scope must be 'global' or 'instance', got: %s", val)
				}
				d.Scope = val
			case "max_memory_mb":
				if !dDisp.NextArg() {
					return dDisp.ArgErr()
				}
				val, err := strconv.Atoi(dDisp.Val())
				if err != nil {
					return dDisp.Errf("invalid max_memory_mb: %v", err)
				}
				d.MaxMemoryMB = val
			case "serve":
				d.EnableServe = true
			case "no_collect":
				d.DisableCollect = true
			default:
				return dDisp.Errf("unknown option: %s", directive)
			}
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var d Dashboard
	err := d.UnmarshalCaddyfile(h.Dispenser)
	return &d, err
}
