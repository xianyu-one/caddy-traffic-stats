package trafficstats

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

// --- 嵌入静态资源 ---
//
//go:embed web
var assets embed.FS

// --- 全局变量与初始化 ---

var (
	globalStats      = newStatsData()
	globalMu         sync.RWMutex
	globalMaxEntries = 100000
)

func init() {
	caddy.RegisterModule(Dashboard{})
	httpcaddyfile.RegisterHandlerDirective("traffic_dashboard", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("traffic_dashboard", httpcaddyfile.Before, "reverse_proxy")
}

// --- 数据结构定义 (保持不变) ---

type StatsData struct {
	TotalRequests   int            `json:"TotalRequests"`
	TotalWebSockets int            `json:"TotalWebSockets"`
	Protocols       map[string]int `json:"Protocols"`
	Codes           map[string]int `json:"Codes"`
	TLSVersions     map[string]int `json:"TLSVersions"`
	CipherSuites    map[string]int `json:"CipherSuites"`
	Curves          map[string]int `json:"Curves"`
	Transports      map[string]int `json:"Transports"`
	IPVersions      map[string]int `json:"IPVersions"`
	ALPN            map[string]int `json:"ALPN"`
	HSTS            map[string]int `json:"HSTS"`
}

type LayoutItem struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	TitleKey  string `json:"title_key"`
	DataKey   string `json:"data_key"`
	GridWidth string `json:"grid_width"`
	ColorVar  string `json:"color_var,omitempty"`
	ColorMode string `json:"color_mode,omitempty"`
}

type DiscoveryResponse struct {
	Scope  string       `json:"scope"`
	Layout []LayoutItem `json:"layout"`
}

type LoginRequest struct {
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
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
	DisableCollect bool   `json:"disable_collect,omitempty"`

	EnableServe  bool   `json:"enable_serve,omitempty"`
	ServeAPIOnly bool   `json:"serve_api_only,omitempty"`
	ServeSecure  bool   `json:"serve_secure,omitempty"`
	PasswordHash string `json:"password_hash,omitempty"`

	logger        *zap.Logger
	instanceStats *StatsData
	instanceMu    sync.RWMutex
	maxEntries    int
	jwtSecret     []byte
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

	if d.PasswordHash != "" {
		d.jwtSecret = []byte(d.PasswordHash)
	} else {
		d.jwtSecret = []byte(fmt.Sprintf("%d", time.Now().UnixNano()))
	}
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
			// 安全检查逻辑
			if d.ServeSecure {
				isLoginEndpoint := r.URL.Path == d.Path+"/login"
				isStaticResource := r.URL.Path == d.Path ||
					r.URL.Path == d.Path+"/" ||
					strings.HasSuffix(r.URL.Path, ".css") ||
					strings.HasSuffix(r.URL.Path, ".js")

				skipAuth := isLoginEndpoint || (!d.ServeAPIOnly && isStaticResource)

				if !skipAuth {
					if !d.checkAuth(r) {
						w.Header().Set("WWW-Authenticate", `Bearer realm="Dashboard"`)
						http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
						return nil
					}
				}
			}

			// 路由分发
			if r.URL.Path == d.Path || r.URL.Path == d.Path+"/" ||
				strings.HasSuffix(r.URL.Path, ".css") ||
				strings.HasSuffix(r.URL.Path, ".js") {

				if d.ServeAPIOnly {
					http.Error(w, "Web dashboard is disabled (API Only mode)", http.StatusNotFound)
					return nil
				}
				return d.serveStatic(w, r)
			}
			if r.URL.Path == d.Path+"/data" {
				return d.serveData(w)
			}
			if r.URL.Path == d.Path+"/discovery" {
				return d.serveDiscovery(w)
			}
			if r.URL.Path == d.Path+"/login" && r.Method == http.MethodPost {
				return d.serveLogin(w, r)
			}
		}
	}

	if d.DisableCollect {
		return next.ServeHTTP(w, r)
	}

	return d.collectAndServe(w, r, next)
}

// --- 静态文件服务逻辑 (修改) ---

func (d *Dashboard) serveStatic(w http.ResponseWriter, r *http.Request) error {
	// 确定请求的文件名
	fileName := "template.html"
	if strings.HasSuffix(r.URL.Path, "style.css") {
		fileName = "style.css"
	} else if strings.HasSuffix(r.URL.Path, "script.js") {
		fileName = "script.js"
	}

	// 修改点：从 web 子目录读取
	content, err := assets.ReadFile("web/" + fileName)
	if err != nil {
		// 开发调试时如果找不到文件，可以打印日志
		d.logger.Error("Failed to load asset", zap.String("file", fileName), zap.Error(err))
		http.Error(w, "Asset not found", http.StatusNotFound)
		return nil
	}

	contentType := mime.TypeByExtension(filepath.Ext(fileName))
	if contentType == "" {
		if strings.HasSuffix(fileName, ".css") {
			contentType = "text/css; charset=utf-8"
		} else if strings.HasSuffix(fileName, ".js") {
			contentType = "application/javascript; charset=utf-8"
		} else {
			contentType = "text/html; charset=utf-8"
		}
	}
	w.Header().Set("Content-Type", contentType)
	w.Write(content)
	return nil
}

// --- 其他逻辑保持不变 ---

func (d *Dashboard) checkAuth(r *http.Request) bool {
	tokenString := ""
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		tokenString = strings.TrimPrefix(authHeader, "Bearer ")
	}
	if tokenString == "" {
		cookie, err := r.Cookie("caddy_stats_token")
		if err == nil {
			tokenString = cookie.Value
		}
	}
	if tokenString == "" {
		return false
	}
	return d.verifyToken(tokenString)
}

func (d *Dashboard) serveLogin(w http.ResponseWriter, r *http.Request) error {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return nil
	}
	inputHash := sha256.Sum256([]byte(req.Password))
	inputHashHex := hex.EncodeToString(inputHash[:])
	if subtle.ConstantTimeCompare([]byte(inputHashHex), []byte(d.PasswordHash)) != 1 {
		time.Sleep(500 * time.Millisecond)
		http.Error(w, `{"error": "Invalid password"}`, http.StatusUnauthorized)
		return nil
	}
	token := d.generateToken()
	http.SetCookie(w, &http.Cookie{
		Name:     "caddy_stats_token",
		Value:    token,
		Path:     d.Path,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		MaxAge:   86400,
	})
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(LoginResponse{Token: token})
}

func (d *Dashboard) generateToken() string {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, d.jwtSecret)
	mac.Write([]byte(ts))
	signature := base64.URLEncoding.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("%s.%s", ts, signature)
}

func (d *Dashboard) verifyToken(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false
	}
	tsStr := parts[0]
	sig := parts[1]
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}
	if time.Now().Unix()-ts > 86400 {
		return false
	}
	mac := hmac.New(sha256.New, d.jwtSecret)
	mac.Write([]byte(tsStr))
	expectedSig := base64.URLEncoding.EncodeToString(mac.Sum(nil))
	return subtle.ConstantTimeCompare([]byte(sig), []byte(expectedSig)) == 1
}

func (d *Dashboard) collectAndServe(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	d.recordRequestInfo(r)
	isWSAttempt := strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
	rec := caddyhttp.NewResponseRecorder(w, nil, nil)
	err := next.ServeHTTP(rec, r)
	d.recordResponseInfo(rec, isWSAttempt)
	return err
}

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

func (d *Dashboard) serveDiscovery(w http.ResponseWriter) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	layout := []LayoutItem{
		{ID: "reqs", Type: "metric", TitleKey: "total_requests", DataKey: "TotalRequests", GridWidth: "half"},
		{ID: "ws", Type: "metric", TitleKey: "total_websockets", DataKey: "TotalWebSockets", GridWidth: "half"},
		{ID: "transport", Type: "chart", TitleKey: "transport", DataKey: "Transports", GridWidth: "half", ColorVar: "--color-transport", ColorMode: "static"},
		{ID: "tls", Type: "chart", TitleKey: "tls_version", DataKey: "TLSVersions", GridWidth: "half", ColorVar: "--color-tls", ColorMode: "static"},
		{ID: "cipher", Type: "chart", TitleKey: "cipher_suites", DataKey: "CipherSuites", GridWidth: "full", ColorVar: "--color-cipher", ColorMode: "static"},
		{ID: "alpn", Type: "chart", TitleKey: "alpn", DataKey: "ALPN", GridWidth: "half", ColorVar: "--color-alpn", ColorMode: "static"},
		{ID: "hsts", Type: "chart", TitleKey: "hsts_status", DataKey: "HSTS", GridWidth: "half", ColorVar: "--color-hsts", ColorMode: "static"},
		{ID: "curves", Type: "chart", TitleKey: "curves", DataKey: "Curves", GridWidth: "full", ColorVar: "--color-curve", ColorMode: "static"},
		{ID: "ip", Type: "chart", TitleKey: "ip_version", DataKey: "IPVersions", GridWidth: "full", ColorVar: "--color-ip", ColorMode: "static"},
		{ID: "proto", Type: "chart", TitleKey: "http_protocols", DataKey: "Protocols", GridWidth: "full", ColorVar: "--color-proto", ColorMode: "static"},
		{ID: "codes", Type: "chart", TitleKey: "response_codes", DataKey: "Codes", GridWidth: "full", ColorMode: "status_code"},
	}
	resp := DiscoveryResponse{Scope: d.Scope, Layout: layout}
	return json.NewEncoder(w).Encode(resp)
}

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
				for dDisp.NextBlock(1) {
					subDirective := dDisp.Val()
					switch subDirective {
					case "api_only":
						d.ServeAPIOnly = true
					case "secure":
						if !dDisp.NextArg() {
							return dDisp.ArgErr()
						}
						d.ServeSecure = true
						pwd := dDisp.Val()
						hash := sha256.Sum256([]byte(pwd))
						d.PasswordHash = hex.EncodeToString(hash[:])
					default:
						return dDisp.Errf("unknown sub-option for serve: %s", subDirective)
					}
				}
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
