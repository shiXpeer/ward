// Package updategateway mediates bounded public update metadata requests.
// Sources are operator configured; this is not an open Internet proxy.
package updategateway

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Source struct {
	Origin     string `json:"origin"`
	PathPrefix string `json:"path_prefix"`
}
type Config struct {
	Sources []Source `json:"sources"`
}
type Request struct {
	URL   string `json:"url"`
	Range string `json:"range,omitempty"`
}
type entry struct {
	status                    int
	body                      []byte
	contentType, contentRange string
	expires                   time.Time
}
type Gateway struct {
	sources []Source
	client  *http.Client
	mu      sync.Mutex
	cache   map[[32]byte]entry
	bytes   int
	slots   chan struct{}
}

const maxBody = 1 << 20
const maxCache = 16 << 20

func New(cfg Config) (*Gateway, error) {
	if len(cfg.Sources) == 0 || len(cfg.Sources) > 256 {
		return nil, errors.New("configure 1–256 update metadata sources")
	}
	for _, s := range cfg.Sources {
		u, e := url.Parse(s.Origin)
		if e != nil || !validURL(u) || u.Path != "" || u.RawQuery != "" || !strings.HasPrefix(s.PathPrefix, "/") || strings.ContainsAny(s.PathPrefix, "?#\\") {
			return nil, errors.New("source must be an HTTPS origin with a path prefix")
		}
	}
	g := &Gateway{sources: append([]Source(nil), cfg.Sources...), cache: make(map[[32]byte]entry), slots: make(chan struct{}, 8)}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.DialContext = publicDial
	transport.MaxConnsPerHost = 2
	transport.ResponseHeaderTimeout = 15 * time.Second
	g.client = &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 4 || !g.allowed(r.URL) {
			return errors.New("unapproved metadata redirect")
		}
		return nil
	}}
	return g, nil
}
func validURL(u *url.URL) bool {
	return u != nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && (u.Port() == "" || u.Port() == "443") && !strings.ContainsAny(u.Path, "\\\x00")
}
func (g *Gateway) allowed(u *url.URL) bool {
	if !validURL(u) || (u.Path != "" && path.Clean(u.Path) != u.Path && path.Clean(u.Path)+"/" != u.Path) {
		return false
	}
	if ip, e := netip.ParseAddr(u.Hostname()); e == nil && !publicIP(ip) {
		return false
	}
	for _, s := range g.sources {
		origin, _ := url.Parse(s.Origin)
		if strings.EqualFold(u.Hostname(), origin.Hostname()) && strings.HasPrefix(metadataPath(u), s.PathPrefix) {
			return true
		}
	}
	return false
}
func metadataPath(u *url.URL) string {
	if u.Path == "" {
		return "/"
	}
	return u.Path
}
func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return false
	}
	for _, p := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32", "2001:10::/28", "2001:20::/28"} {
		if netip.MustParsePrefix(p).Contains(ip) {
			return false
		}
	}
	return true
}
func publicDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil || port != "443" {
		return nil, errors.New("HTTPS port required")
	}
	ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if e != nil {
		return nil, e
	}
	if len(ips) == 0 {
		return nil, errors.New("empty DNS response")
	}
	// Reject mixed public/private answers. Connect to the validated IP rather than
	// resolving the name again, so DNS rebinding cannot reach a private address.
	for _, ip := range ips {
		if !publicIP(ip) {
			return nil, errors.New("non-public update destination")
		}
	}
	dialer := net.Dialer{Timeout: 10 * time.Second}
	var last error
	for _, ip := range ips {
		c, e := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if e == nil {
			return c, nil
		}
		last = e
	}
	return nil, last
}
func validRange(value string) bool {
	if value == "" {
		return true
	}
	if !strings.HasPrefix(value, "bytes=") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(value, "bytes="), "-")
	if len(parts) != 2 {
		return false
	}
	a, e := strconv.ParseUint(parts[0], 10, 63)
	if e != nil {
		return false
	}
	b, e := strconv.ParseUint(parts[1], 10, 63)
	return e == nil && b >= a && b-a < maxBody && b < 8<<30
}
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "POST required", 405)
		return
	}
	var request Request
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	dec.DisallowUnknownFields()
	if dec.Decode(&request) != nil || dec.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid metadata request", 400)
		return
	}
	u, e := url.Parse(request.URL)
	if e != nil || !g.allowed(u) || !validRange(request.Range) {
		http.Error(w, "metadata source is not approved", 403)
		return
	}
	key := sha256.Sum256([]byte(request.URL + "\n" + request.Range))
	g.mu.Lock()
	cached, ok := g.cache[key]
	g.mu.Unlock()
	if ok && time.Now().Before(cached.expires) {
		write(w, cached)
		return
	}
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		http.Error(w, "metadata service busy", 429)
		return
	}
	req, e := http.NewRequestWithContext(r.Context(), http.MethodGet, request.URL, nil)
	if e != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	req.Header.Set("User-Agent", "shixpeer-ward-metadata")
	if request.Range != "" {
		req.Header.Set("Accept-Encoding", "identity")
		req.Header.Set("Range", request.Range)
	}
	resp, e := g.client.Do(req)
	if e != nil {
		http.Error(w, "upstream metadata unavailable", 502)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 204 && resp.StatusCode != 206 {
		http.Error(w, "upstream metadata unavailable", 502)
		return
	}
	if (request.Range != "" && resp.StatusCode != 206) || (request.Range == "" && resp.StatusCode == 206) {
		http.Error(w, "unexpected upstream range response", 502)
		return
	}
	body, e := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if e != nil || len(body) > maxBody {
		http.Error(w, "metadata exceeds limit", 502)
		return
	}
	if resp.StatusCode == 206 {
		expected := strings.TrimPrefix(request.Range, "bytes=")
		if !strings.HasPrefix(resp.Header.Get("Content-Range"), "bytes "+expected+"/") {
			http.Error(w, "invalid upstream range", 502)
			return
		}
	}
	result := entry{status: resp.StatusCode, body: body, contentType: resp.Header.Get("Content-Type"), contentRange: resp.Header.Get("Content-Range"), expires: time.Now().Add(10 * time.Minute)}
	g.mu.Lock()
	// Both entry count and aggregate bytes are bounded, including expired data.
	if len(g.cache) >= 128 || g.bytes+len(body) > maxCache {
		g.cache = make(map[[32]byte]entry)
		g.bytes = 0
	}
	if previous, exists := g.cache[key]; exists {
		g.bytes -= len(previous.body)
	}
	g.cache[key] = result
	g.bytes += len(body)
	g.mu.Unlock()
	write(w, result)
}
func write(w http.ResponseWriter, result entry) {
	if result.contentType != "" {
		w.Header().Set("Content-Type", result.contentType)
	}
	if result.contentRange != "" {
		w.Header().Set("Content-Range", result.contentRange)
	}
	w.WriteHeader(result.status)
	_, _ = w.Write(result.body)
}
func (g *Gateway) String() string {
	return fmt.Sprintf("update metadata gateway (%d configured sources)", len(g.sources))
}
