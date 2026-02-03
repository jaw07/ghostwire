package obfuscation

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ProbeResistanceConfig configures active probe resistance
type ProbeResistanceConfig struct {
	// Enabled turns probe resistance on/off
	Enabled bool

	// CoverSite is the website to serve to probers
	CoverSite *CoverSiteConfig

	// KnockSequence defines the authentication sequence
	KnockSequence *KnockConfig

	// ResponseDelay adds delay to unauthenticated requests
	ResponseDelay time.Duration

	// RateLimiter limits requests from unknown sources
	RateLimiter *RateLimitConfig

	// BehaviorMimicry mimics real server behavior
	BehaviorMimicry bool
}

// CoverSiteConfig configures the cover website
type CoverSiteConfig struct {
	// RootDir contains static files to serve
	RootDir string

	// IndexFile is the default page
	IndexFile string

	// ServerHeader is the Server response header
	ServerHeader string

	// MimicTarget is a real site to proxy/mimic
	MimicTarget string

	// StaticResponses for common paths
	StaticResponses map[string]*StaticResponse
}

// StaticResponse defines a canned response
type StaticResponse struct {
	StatusCode  int
	Headers     map[string]string
	Body        []byte
	ContentType string
}

// KnockConfig configures knock sequence authentication
type KnockConfig struct {
	// MeshSecret is the shared secret
	MeshSecret []byte

	// Window is the time window for valid knocks
	Window time.Duration

	// Path is the knock endpoint path
	Path string

	// HeaderName is the header containing knock data
	HeaderName string

	// CookieName is the cookie containing knock data
	CookieName string
}

// RateLimitConfig configures rate limiting
type RateLimitConfig struct {
	// RequestsPerSecond per IP
	RequestsPerSecond float64

	// BurstSize allowed
	BurstSize int

	// BlockDuration after exceeding limit
	BlockDuration time.Duration
}

// DefaultProbeResistanceConfig returns default configuration
func DefaultProbeResistanceConfig() *ProbeResistanceConfig {
	return &ProbeResistanceConfig{
		Enabled:       true,
		ResponseDelay: 50 * time.Millisecond,
		CoverSite: &CoverSiteConfig{
			IndexFile:    "index.html",
			ServerHeader: "nginx/1.24.0",
			StaticResponses: map[string]*StaticResponse{
				"/": {
					StatusCode:  200,
					ContentType: "text/html; charset=utf-8",
					Body:        defaultIndexHTML,
				},
				"/favicon.ico": {
					StatusCode:  204,
					ContentType: "image/x-icon",
				},
				"/robots.txt": {
					StatusCode:  200,
					ContentType: "text/plain",
					Body:        []byte("User-agent: *\nDisallow: /"),
				},
			},
		},
		KnockSequence: &KnockConfig{
			Window:     30 * time.Second,
			Path:       "/api/v1/check",
			HeaderName: "X-Request-ID",
			CookieName: "session",
		},
		RateLimiter: &RateLimitConfig{
			RequestsPerSecond: 10,
			BurstSize:         20,
			BlockDuration:     5 * time.Minute,
		},
		BehaviorMimicry: true,
	}
}

var defaultIndexHTML = []byte(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
               display: flex; justify-content: center; align-items: center;
               height: 100vh; margin: 0; background: #f5f5f5; }
        .container { text-align: center; }
        h1 { color: #333; font-weight: 300; }
        p { color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome</h1>
        <p>This server is functioning normally.</p>
    </div>
</body>
</html>`)

// ProbeResistantServer wraps an HTTP server with probe resistance
type ProbeResistantServer struct {
	cfg         *ProbeResistanceConfig
	realHandler http.Handler
	rateLimiter *rateLimiter
	mu          sync.RWMutex
}

// NewProbeResistantServer creates a probe-resistant server wrapper
func NewProbeResistantServer(cfg *ProbeResistanceConfig, realHandler http.Handler) *ProbeResistantServer {
	if cfg == nil {
		cfg = DefaultProbeResistanceConfig()
	}

	return &ProbeResistantServer{
		cfg:         cfg,
		realHandler: realHandler,
		rateLimiter: newRateLimiter(cfg.RateLimiter),
	}
}

// ServeHTTP handles requests with probe resistance
func (s *ProbeResistantServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP := extractClientIP(r)

	// Rate limiting check
	if s.rateLimiter != nil && !s.rateLimiter.Allow(clientIP) {
		s.serveCover(w, r, http.StatusTooManyRequests)
		return
	}

	// Check for valid knock
	if s.isValidKnock(r) {
		// Authenticated request - pass to real handler
		s.realHandler.ServeHTTP(w, r)
		return
	}

	// Add response delay to slow down probers
	if s.cfg.ResponseDelay > 0 {
		// Add jitter to delay
		jitter := time.Duration(randInt(int(s.cfg.ResponseDelay / 2)))
		time.Sleep(s.cfg.ResponseDelay + jitter)
	}

	// Serve cover site
	s.serveCover(w, r, 0)
}

// isValidKnock checks if the request contains a valid knock sequence
func (s *ProbeResistantServer) isValidKnock(r *http.Request) bool {
	if s.cfg.KnockSequence == nil || len(s.cfg.KnockSequence.MeshSecret) == 0 {
		return false
	}

	knock := s.cfg.KnockSequence

	// Check path
	if knock.Path != "" && !strings.HasPrefix(r.URL.Path, knock.Path) {
		return false
	}

	// Extract knock data from header or cookie
	var knockData string
	if knock.HeaderName != "" {
		knockData = r.Header.Get(knock.HeaderName)
	}
	if knockData == "" && knock.CookieName != "" {
		if cookie, err := r.Cookie(knock.CookieName); err == nil {
			knockData = cookie.Value
		}
	}

	if knockData == "" {
		return false
	}

	// Validate knock
	return s.validateKnock(knockData)
}

// validateKnock validates a knock sequence
func (s *ProbeResistantServer) validateKnock(knock string) bool {
	// Expected format: timestamp:hmac
	parts := strings.Split(knock, ":")
	if len(parts) != 2 {
		return false
	}

	timestampStr := parts[0]
	providedHMAC := parts[1]

	// Parse timestamp
	var timestamp int64
	fmt.Sscanf(timestampStr, "%d", &timestamp)

	// Check timestamp freshness
	now := time.Now().Unix()
	window := int64(s.cfg.KnockSequence.Window.Seconds())
	if abs64(now-timestamp) > window {
		return false
	}

	// Compute expected HMAC
	h := sha256.New()
	h.Write(s.cfg.KnockSequence.MeshSecret)
	binary.Write(h, binary.BigEndian, timestamp)
	expectedHMAC := fmt.Sprintf("%x", h.Sum(nil)[:16])

	// Constant-time comparison
	if len(providedHMAC) != len(expectedHMAC) {
		return false
	}

	result := 0
	for i := 0; i < len(expectedHMAC); i++ {
		result |= int(providedHMAC[i] ^ expectedHMAC[i])
	}

	return result == 0
}

// serveCover serves the cover site response
func (s *ProbeResistantServer) serveCover(w http.ResponseWriter, r *http.Request, statusOverride int) {
	cover := s.cfg.CoverSite

	// Set common headers
	w.Header().Set("Server", cover.ServerHeader)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")

	// Check for static response
	if resp, ok := cover.StaticResponses[r.URL.Path]; ok {
		if statusOverride > 0 {
			w.WriteHeader(statusOverride)
		} else {
			w.WriteHeader(resp.StatusCode)
		}
		if resp.ContentType != "" {
			w.Header().Set("Content-Type", resp.ContentType)
		}
		for k, v := range resp.Headers {
			w.Header().Set(k, v)
		}
		w.Write(resp.Body)
		return
	}

	// Default: serve index or 404
	if r.URL.Path == "/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write(defaultIndexHTML)
		return
	}

	// 404 for unknown paths
	http.NotFound(w, r)
}

// GenerateKnock creates a valid knock sequence
func GenerateKnock(meshSecret []byte) string {
	timestamp := time.Now().Unix()

	h := sha256.New()
	h.Write(meshSecret)
	binary.Write(h, binary.BigEndian, timestamp)
	hmac := fmt.Sprintf("%x", h.Sum(nil)[:16])

	return fmt.Sprintf("%d:%s", timestamp, hmac)
}

// rateLimiter implements token bucket rate limiting per IP
type rateLimiter struct {
	cfg      *RateLimitConfig
	buckets  map[string]*bucket
	blocked  map[string]time.Time
	mu       sync.RWMutex
}

type bucket struct {
	tokens   float64
	lastTime time.Time
}

func newRateLimiter(cfg *RateLimitConfig) *rateLimiter {
	if cfg == nil {
		return nil
	}
	return &rateLimiter{
		cfg:     cfg,
		buckets: make(map[string]*bucket),
		blocked: make(map[string]time.Time),
	}
}

func (rl *rateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Check if blocked
	if blockUntil, ok := rl.blocked[ip]; ok {
		if time.Now().Before(blockUntil) {
			return false
		}
		delete(rl.blocked, ip)
	}

	// Get or create bucket
	b, ok := rl.buckets[ip]
	if !ok {
		b = &bucket{
			tokens:   float64(rl.cfg.BurstSize),
			lastTime: time.Now(),
		}
		rl.buckets[ip] = b
	}

	// Refill tokens
	now := time.Now()
	elapsed := now.Sub(b.lastTime).Seconds()
	b.tokens += elapsed * rl.cfg.RequestsPerSecond
	if b.tokens > float64(rl.cfg.BurstSize) {
		b.tokens = float64(rl.cfg.BurstSize)
	}
	b.lastTime = now

	// Check tokens
	if b.tokens < 1 {
		// Block this IP
		rl.blocked[ip] = now.Add(rl.cfg.BlockDuration)
		return false
	}

	b.tokens--
	return true
}

// ProbeDetector detects active probing attempts
type ProbeDetector struct {
	patterns   []ProbePattern
	detections map[string][]time.Time // IP -> detection times
	mu         sync.RWMutex
}

// ProbePattern defines a pattern that indicates probing
type ProbePattern struct {
	Name        string
	Description string
	Detect      func(r *http.Request, body []byte) bool
}

// CommonProbePatterns returns patterns for detecting common probes
func CommonProbePatterns() []ProbePattern {
	return []ProbePattern{
		{
			Name:        "wireguard_handshake",
			Description: "WireGuard handshake initiation",
			Detect: func(r *http.Request, body []byte) bool {
				// WireGuard initiation is always 148 bytes with type 0x01
				return len(body) == 148 && len(body) > 0 && body[0] == 0x01
			},
		},
		{
			Name:        "shadowsocks_probe",
			Description: "Shadowsocks protocol probe",
			Detect: func(r *http.Request, body []byte) bool {
				// Shadowsocks often starts with random-looking bytes
				// Check for high entropy short messages
				if len(body) < 10 || len(body) > 100 {
					return false
				}
				return entropy(body) > 7.5
			},
		},
		{
			Name:        "replay_attack",
			Description: "Replayed authentication attempt",
			Detect: func(r *http.Request, body []byte) bool {
				// Check for exact replay (would need state)
				return false
			},
		},
		{
			Name:        "scanning_ua",
			Description: "Known scanner user agent",
			Detect: func(r *http.Request, body []byte) bool {
				ua := strings.ToLower(r.UserAgent())
				scanners := []string{"nmap", "masscan", "zgrab", "censys", "shodan"}
				for _, s := range scanners {
					if strings.Contains(ua, s) {
						return true
					}
				}
				return false
			},
		},
		{
			Name:        "invalid_http",
			Description: "Invalid HTTP request",
			Detect: func(r *http.Request, body []byte) bool {
				// Check for non-HTTP traffic on HTTP port
				if r.Method == "" || r.URL == nil {
					return true
				}
				return false
			},
		},
	}
}

// NewProbeDetector creates a probe detector
func NewProbeDetector(patterns []ProbePattern) *ProbeDetector {
	if patterns == nil {
		patterns = CommonProbePatterns()
	}
	return &ProbeDetector{
		patterns:   patterns,
		detections: make(map[string][]time.Time),
	}
}

// Detect checks a request for probe patterns
func (pd *ProbeDetector) Detect(r *http.Request, body []byte) []string {
	var matches []string

	for _, pattern := range pd.patterns {
		if pattern.Detect(r, body) {
			matches = append(matches, pattern.Name)
		}
	}

	if len(matches) > 0 {
		ip := extractClientIP(r)
		pd.mu.Lock()
		pd.detections[ip] = append(pd.detections[ip], time.Now())
		pd.mu.Unlock()
	}

	return matches
}

// IsKnownProber checks if an IP has been flagged as probing
func (pd *ProbeDetector) IsKnownProber(ip string) bool {
	pd.mu.RLock()
	defer pd.mu.RUnlock()

	detections := pd.detections[ip]
	if len(detections) < 3 {
		return false
	}

	// Check for recent detections (last hour)
	recent := 0
	cutoff := time.Now().Add(-1 * time.Hour)
	for _, t := range detections {
		if t.After(cutoff) {
			recent++
		}
	}

	return recent >= 3
}

// ProbeResistantListener wraps a listener with probe detection
type ProbeResistantListener struct {
	net.Listener
	detector *ProbeDetector
	handler  func(net.Conn) bool // Returns true if connection should proceed
}

// NewProbeResistantListener creates a probe-resistant listener
func NewProbeResistantListener(l net.Listener, detector *ProbeDetector) *ProbeResistantListener {
	return &ProbeResistantListener{
		Listener: l,
		detector: detector,
	}
}

// Accept accepts connections with probe detection
func (prl *ProbeResistantListener) Accept() (net.Conn, error) {
	for {
		conn, err := prl.Listener.Accept()
		if err != nil {
			return nil, err
		}

		// Check if IP is known prober
		remoteIP := extractIPFromAddr(conn.RemoteAddr())
		if prl.detector != nil && prl.detector.IsKnownProber(remoteIP) {
			// Close silently or serve cover
			conn.Close()
			continue
		}

		// Peek at initial bytes for protocol detection
		bufConn := newBufferedConn(conn)
		peek, _ := bufConn.Peek(10)

		// Check for obvious non-HTTP/TLS traffic
		if !looksLikeHTTP(peek) && !looksLikeTLS(peek) {
			// Not expected protocol - close
			conn.Close()
			continue
		}

		return bufConn, nil
	}
}

// bufferedConn allows peeking at initial bytes
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func newBufferedConn(conn net.Conn) *bufferedConn {
	return &bufferedConn{
		Conn:   conn,
		reader: bufio.NewReader(conn),
	}
}

func (bc *bufferedConn) Peek(n int) ([]byte, error) {
	return bc.reader.Peek(n)
}

func (bc *bufferedConn) Read(b []byte) (int, error) {
	return bc.reader.Read(b)
}

// looksLikeHTTP checks if bytes look like HTTP
func looksLikeHTTP(b []byte) bool {
	if len(b) < 3 {
		return false
	}
	methods := []string{"GET", "POS", "PUT", "DEL", "HEA", "OPT", "PAT", "CON"}
	prefix := string(b[:3])
	for _, m := range methods {
		if prefix == m {
			return true
		}
	}
	return false
}

// looksLikeTLS checks if bytes look like TLS
func looksLikeTLS(b []byte) bool {
	if len(b) < 3 {
		return false
	}
	// TLS record: ContentType (1 byte) + Version (2 bytes)
	// ContentType 0x16 = Handshake, Version 0x0301, 0x0302, 0x0303
	if b[0] == 0x16 && b[1] == 0x03 && (b[2] >= 0x01 && b[2] <= 0x04) {
		return true
	}
	return false
}

// Helper functions

func extractClientIP(r *http.Request) string {
	// Check X-Forwarded-For first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to RemoteAddr
	return extractIPFromAddr(r.RemoteAddr)
}

func extractIPFromAddr(addr interface{}) string {
	var addrStr string
	switch a := addr.(type) {
	case string:
		addrStr = a
	case net.Addr:
		addrStr = a.String()
	default:
		return ""
	}

	host, _, err := net.SplitHostPort(addrStr)
	if err != nil {
		return addrStr
	}
	return host
}

func randInt(max int) int {
	if max <= 0 {
		return 0
	}
	b := make([]byte, 4)
	rand.Read(b)
	return int(binary.BigEndian.Uint32(b)) % max
}

func abs64(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

func entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count byte frequencies
	freq := make([]int, 256)
	for _, b := range data {
		freq[b]++
	}

	// Calculate entropy
	var ent float64
	size := float64(len(data))
	for _, f := range freq {
		if f > 0 {
			p := float64(f) / size
			ent -= p * log2(p)
		}
	}

	return ent
}

func log2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// Approximate log2 using natural log
	return 1.4426950408889634 * ln(x)
}

func ln(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// Simple Taylor series approximation
	// For better accuracy, use math.Log
	if x < 1 {
		return -ln(1 / x)
	}
	result := 0.0
	y := (x - 1) / (x + 1)
	y2 := y * y
	for i := 1; i < 100; i += 2 {
		result += y / float64(i)
		y *= y2
	}
	return 2 * result
}

// CoverSiteProxy proxies requests to a real cover site
type CoverSiteProxy struct {
	targetURL string
	client    *http.Client
}

// NewCoverSiteProxy creates a proxy to a cover site
func NewCoverSiteProxy(targetURL string) *CoverSiteProxy {
	return &CoverSiteProxy{
		targetURL: targetURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ServeHTTP proxies requests to the cover site
func (p *CoverSiteProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Build proxied request
	proxyURL := p.targetURL + r.URL.Path
	if r.URL.RawQuery != "" {
		proxyURL += "?" + r.URL.RawQuery
	}

	proxyReq, err := http.NewRequest(r.Method, proxyURL, r.Body)
	if err != nil {
		http.Error(w, "proxy error", http.StatusBadGateway)
		return
	}

	// Copy safe headers
	safeHeaders := []string{"Accept", "Accept-Language", "Accept-Encoding", "User-Agent"}
	for _, h := range safeHeaders {
		if v := r.Header.Get(h); v != "" {
			proxyReq.Header.Set(h, v)
		}
	}

	// Execute request
	resp, err := p.client.Do(proxyReq)
	if err != nil {
		http.Error(w, "proxy error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// InitialDataReader wraps a reader with initial buffered data
type InitialDataReader struct {
	initial []byte
	pos     int
	reader  io.Reader
}

// NewInitialDataReader creates a reader with prepended data
func NewInitialDataReader(initial []byte, r io.Reader) *InitialDataReader {
	return &InitialDataReader{
		initial: initial,
		reader:  r,
	}
}

func (idr *InitialDataReader) Read(p []byte) (int, error) {
	if idr.pos < len(idr.initial) {
		n := copy(p, idr.initial[idr.pos:])
		idr.pos += n
		return n, nil
	}
	return idr.reader.Read(p)
}

// MultiReader combines initial data with underlying reader
func MultiReader(initial []byte, r io.Reader) io.Reader {
	return io.MultiReader(bytes.NewReader(initial), r)
}
