package trafficstats

import (
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"fmt"
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

// --- 全局变量与初始化 ---

var (
	// globalStats 存储全局聚合统计数据
	globalStats      = newStatsData()
	globalMu         sync.RWMutex
	globalMaxEntries = 100000
)

func init() {
	caddy.RegisterModule(Dashboard{})
	httpcaddyfile.RegisterHandlerDirective("traffic_dashboard", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("traffic_dashboard", httpcaddyfile.Before, "reverse_proxy")
}

// --- 数据结构定义 ---

// StatsData 核心统计数据结构
type StatsData struct {
	TotalRequests   int            `json:"TotalRequests"`
	TotalWebSockets int            `json:"TotalWebSockets"`
	Protocols       map[string]int `json:"Protocols"`
	Codes           map[string]int `json:"Codes"`
	TLSVersions     map[string]int `json:"TLSVersions"`
	CipherSuites    map[string]int `json:"CipherSuites"`
	Curves          map[string]int `json:"Curves"` // Go 1.24+
	Transports      map[string]int `json:"Transports"`
	IPVersions      map[string]int `json:"IPVersions"`
	ALPN            map[string]int `json:"ALPN"`
	HSTS            map[string]int `json:"HSTS"`
}

// LayoutItem 定义前端卡片的布局和属性
type LayoutItem struct {
	ID        string `json:"id"`
	Type      string `json:"type"`                 // "metric" (数字) 或 "chart" (条形图)
	TitleKey  string `json:"title_key"`            // i18n 键值
	DataKey   string `json:"data_key"`             // 对应 StatsData 中的字段名
	GridWidth string `json:"grid_width"`           // "half" 或 "full"
	ColorVar  string `json:"color_var,omitempty"`  // CSS 变量名 (用于单一颜色)
	ColorMode string `json:"color_mode,omitempty"` // "static" 或 "status_code" (用于动态颜色)
}

// DiscoveryResponse 服务发现响应结构
type DiscoveryResponse struct {
	Scope  string       `json:"scope"`
	Layout []LayoutItem `json:"layout"`
}

func newStatsData() *StatsData {
	return &StatsData{
		Protocols:    make(map[string]int),
		Codes:        make(map[string]int),
		TLSVersions:  make(map[string]int),
		CipherSuites: make(map[string]int),
		Curves:       make(map[string]int),
		Transports:   make(map[string]int),
		IPVersions:   make(map[string]int),
		ALPN:         make(map[string]int),
		HSTS:         make(map[string]int),
	}
}

// Dashboard Caddy 模块结构体
type Dashboard struct {
	Path           string `json:"path,omitempty"`
	Scope          string `json:"scope,omitempty"`
	MaxMemoryMB    int    `json:"max_memory_mb,omitempty"`
	EnableServe    bool   `json:"enable_serve,omitempty"`
	DisableCollect bool   `json:"disable_collect,omitempty"`

	logger        *zap.Logger
	instanceStats *StatsData
	instanceMu    sync.RWMutex
	maxEntries    int
}

func (Dashboard) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.traffic_dashboard",
		New: func() caddy.Module { return new(Dashboard) },
	}
}

func (d *Dashboard) Provision(ctx caddy.Context) error {
	d.logger = ctx.Logger(d)
	d.provisionDefaults()
	d.provisionLimits()
	d.instanceStats = newStatsData()
	return nil
}

func (d *Dashboard) provisionDefaults() {
	if d.Path == "" {
		d.Path = "/traffic"
	}
	d.Path = strings.TrimRight(d.Path, "/")
	if d.Scope == "" {
		d.Scope = "instance"
	}
	if d.MaxMemoryMB <= 0 {
		d.MaxMemoryMB = 64
	}
}

func (d *Dashboard) provisionLimits() {
	d.maxEntries = (d.MaxMemoryMB * 1024 * 1024) / 256
	if d.maxEntries < 1000 {
		d.maxEntries = 1000
	}
}

func (d *Dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if d.EnableServe {
		if strings.HasPrefix(r.URL.Path, d.Path) {
			// 1. 静态 HTML 页面
			if r.URL.Path == d.Path || r.URL.Path == d.Path+"/" {
				return d.serveStatic(w)
			}
			// 2. 数据 API
			if r.URL.Path == d.Path+"/data" {
				return d.serveData(w)
			}
			// 3. 发现/配置 API
			if r.URL.Path == d.Path+"/discovery" {
				return d.serveDiscovery(w)
			}
		}
	}

	if d.DisableCollect {
		return next.ServeHTTP(w, r)
	}

	return d.collectAndServe(w, r, next)
}

func (d *Dashboard) collectAndServe(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	d.recordRequestInfo(r)
	isWSAttempt := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
	rec := caddyhttp.NewResponseRecorder(w, nil, nil)
	err := next.ServeHTTP(rec, r)
	d.recordResponseInfo(rec, isWSAttempt)
	return err
}

// --- 数据采集逻辑 (保持不变) ---

func (d *Dashboard) recordRequestInfo(r *http.Request) {
	proto := r.Proto
	if proto == "" {
		proto = "Unknown"
	}
	tlsVer, cipherSuite, curve, alpn := resolveTLSDetails(r.TLS)
	transport := resolveTransport(proto)
	ipVer := resolveIPVersion(r.RemoteAddr)

	d.batchUpdateStats(func(s *StatsData, limit int) {
		s.TotalRequests++
		safeIncrement(s.Protocols, proto, limit)
		safeIncrement(s.TLSVersions, tlsVer, limit)
		safeIncrement(s.Transports, transport, limit)
		safeIncrement(s.IPVersions, ipVer, limit)
		safeIncrement(s.CipherSuites, cipherSuite, limit)
		safeIncrement(s.Curves, curve, limit)
		safeIncrement(s.ALPN, alpn, limit)
	})
}

func (d *Dashboard) recordResponseInfo(rec caddyhttp.ResponseRecorder, isWSAttempt bool) {
	code := fmt.Sprintf("%d", rec.Status())
	isWSSuccess := isWSAttempt && rec.Status() == 101
	hstsStatus := "Disabled"
	if val := rec.Header().Get("Strict-Transport-Security"); val != "" {
		hstsStatus = "Enabled"
	}

	d.batchUpdateStats(func(s *StatsData, limit int) {
		safeIncrement(s.Codes, code, limit)
		safeIncrement(s.HSTS, hstsStatus, limit)
		if isWSSuccess {
			s.TotalWebSockets++
		}
	})
}

func (d *Dashboard) batchUpdateStats(updateFn func(*StatsData, int)) {
	globalMu.Lock()
	updateFn(globalStats, globalMaxEntries)
	globalMu.Unlock()

	d.instanceMu.Lock()
	updateFn(d.instanceStats, d.maxEntries)
	d.instanceMu.Unlock()
}

func safeIncrement(m map[string]int, key string, limit int) {
	if len(m) < limit || m[key] > 0 {
		m[key]++
	}
}

// resolveTLSDetails, resolveTransport, resolveIPVersion 保持不变...
func resolveTLSDetails(state *tls.ConnectionState) (ver, suite, curve, alpn string) {
	if state == nil {
		return "No TLS", "No TLS", "None", "None"
	}
	switch state.Version {
	case tls.VersionTLS10:
		ver = "TLS 1.0"
	case tls.VersionTLS11:
		ver = "TLS 1.1"
	case tls.VersionTLS12:
		ver = "TLS 1.2"
	case tls.VersionTLS13:
		ver = "TLS 1.3"
	default:
		ver = "Unknown TLS"
	}
	suite = tls.CipherSuiteName(state.CipherSuite)
	if suite == "" {
		suite = fmt.Sprintf("0x%04x", state.CipherSuite)
	}
	// Go 1.24+ check
	curveID := state.CurveID
	curve = curveID.String()
	if curve == "" || strings.HasPrefix(curve, "CurveID(") {
		curve = fmt.Sprintf("Curve(0x%04x)", uint16(curveID))
	}
	alpn = state.NegotiatedProtocol
	if alpn == "" {
		alpn = "No ALPN"
	}
	return
}

func resolveTransport(proto string) string {
	if strings.HasPrefix(proto, "HTTP/3") {
		return "QUIC"
	}
	if strings.HasPrefix(proto, "HTTP/1") || strings.HasPrefix(proto, "HTTP/2") {
		return "TCP"
	}
	return "Other"
}

func resolveIPVersion(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	host = strings.TrimSpace(host)
	host = strings.Trim(host, "[]")
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

// serveStatic 直接返回静态 HTML
func (d *Dashboard) serveStatic(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 简单粗暴，直接写回字符串，不再进行模板解析
	_, err := w.Write([]byte(dashboardHTML))
	return err
}

// serveDiscovery 返回 UI 布局配置
func (d *Dashboard) serveDiscovery(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	// 定义布局配置 (后端控制前端渲染逻辑)
	layout := []LayoutItem{
		// 顶部指标
		{ID: "reqs", Type: "metric", TitleKey: "total_requests", DataKey: "TotalRequests", GridWidth: "half"},
		{ID: "ws", Type: "metric", TitleKey: "total_websockets", DataKey: "TotalWebSockets", GridWidth: "half"},

		// 协议与版本
		{ID: "transport", Type: "chart", TitleKey: "transport", DataKey: "Transports", GridWidth: "half", ColorVar: "--color-transport", ColorMode: "static"},
		{ID: "tls", Type: "chart", TitleKey: "tls_version", DataKey: "TLSVersions", GridWidth: "half", ColorVar: "--color-tls", ColorMode: "static"},

		// 安全详情
		{ID: "cipher", Type: "chart", TitleKey: "cipher_suites", DataKey: "CipherSuites", GridWidth: "full", ColorVar: "--color-cipher", ColorMode: "static"},
		{ID: "alpn", Type: "chart", TitleKey: "alpn", DataKey: "ALPN", GridWidth: "half", ColorVar: "--color-alpn", ColorMode: "static"},
		{ID: "hsts", Type: "chart", TitleKey: "hsts_status", DataKey: "HSTS", GridWidth: "half", ColorVar: "--color-hsts", ColorMode: "static"},
		{ID: "curves", Type: "chart", TitleKey: "curves", DataKey: "Curves", GridWidth: "full", ColorVar: "--color-curve", ColorMode: "static"},

		// 其它
		{ID: "ip", Type: "chart", TitleKey: "ip_version", DataKey: "IPVersions", GridWidth: "full", ColorVar: "--color-ip", ColorMode: "static"},
		{ID: "proto", Type: "chart", TitleKey: "http_protocols", DataKey: "Protocols", GridWidth: "full", ColorVar: "--color-proto", ColorMode: "static"},
		{ID: "codes", Type: "chart", TitleKey: "response_codes", DataKey: "Codes", GridWidth: "full", ColorMode: "status_code"},
	}

	resp := DiscoveryResponse{
		Scope:  d.Scope,
		Layout: layout,
	}

	return json.NewEncoder(w).Encode(resp)
}

// serveData 返回实时统计数据
func (d *Dashboard) serveData(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	snapshot := d.getSnapshot()
	return json.NewEncoder(w).Encode(snapshot)
}

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

func cloneStats(src *StatsData) *StatsData {
	dst := newStatsData()
	dst.TotalRequests = src.TotalRequests
	dst.TotalWebSockets = src.TotalWebSockets
	copyMap(dst.Protocols, src.Protocols)
	copyMap(dst.Codes, src.Codes)
	copyMap(dst.TLSVersions, src.TLSVersions)
	copyMap(dst.Transports, src.Transports)
	copyMap(dst.IPVersions, src.IPVersions)
	copyMap(dst.CipherSuites, src.CipherSuites)
	copyMap(dst.Curves, src.Curves)
	copyMap(dst.ALPN, src.ALPN)
	copyMap(dst.HSTS, src.HSTS)
	return dst
}

func copyMap(dst, src map[string]int) {
	for k, v := range src {
		dst[k] = v
	}
}

// --- 配置解析 ---

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
