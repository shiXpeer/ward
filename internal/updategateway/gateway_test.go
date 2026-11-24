package updategateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func gateway(t *testing.T) *Gateway {
	t.Helper()
	g, e := New(Config{Sources: []Source{{Origin: "https://updates.example", PathPrefix: "/public/"}}})
	if e != nil {
		t.Fatal(e)
	}
	return g
}
func request(t *testing.T, g *Gateway, v Request) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(v)
	w := httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest("POST", "/v1/update-metadata", bytes.NewReader(raw)))
	return w
}
func TestMetadataAndCache(t *testing.T) {
	g := gateway(t)
	calls := 0
	g.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "GET" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Fatal("credential forwarding")
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"version":"2.0"}`))}, nil
	})
	for i := 0; i < 2; i++ {
		w := request(t, g, Request{URL: "https://updates.example/public/latest"})
		if w.Code != 200 || !strings.Contains(w.Body.String(), "2.0") {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if calls != 1 {
		t.Fatal("cache miss", calls)
	}
}
func TestRejectedDestinationsAndInputs(t *testing.T) {
	g := gateway(t)
	g.client.Transport = roundTrip(func(*http.Request) (*http.Response, error) { t.Fatal("unapproved network request"); return nil, nil })
	for _, raw := range []string{"http://updates.example/public/a", "https://updates.example:22/public/a", "https://user:pass@updates.example/public/a", "https://evil.example/public/a", "https://updates.example/private/a", "https://127.0.0.1/public/a"} {
		if w := request(t, g, Request{URL: raw}); w.Code != 403 {
			t.Fatal(raw, w.Code)
		}
	}
	for _, value := range []string{"bytes=0-1048576", "bytes=10-2", "bytes=0-", "bytes=0-3,5-7"} {
		if w := request(t, g, Request{URL: "https://updates.example/public/a", Range: value}); w.Code != 403 {
			t.Fatal(value, w.Code)
		}
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest("GET", "/v1/update-metadata", nil))
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
	w = httptest.NewRecorder()
	g.ServeHTTP(w, httptest.NewRequest("POST", "/v1/update-metadata", strings.NewReader(`{"url":"x","headers":{"Authorization":"secret"}}`)))
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
}
func TestRangeAndBounds(t *testing.T) {
	g := gateway(t)
	g.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Header.Get("Range") != "bytes=0-3" {
			t.Fatal("range missing")
		}
		return &http.Response{StatusCode: 206, Header: http.Header{"Content-Range": []string{"bytes 0-3/99"}}, Body: io.NopCloser(strings.NewReader("xar!"))}, nil
	})
	if w := request(t, g, Request{URL: "https://updates.example/public/package.pkg", Range: "bytes=0-3"}); w.Code != 206 || w.Body.String() != "xar!" {
		t.Fatal(w.Code, w.Body.String())
	}
	g.client.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", maxBody+1)))}, nil
	})
	if w := request(t, g, Request{URL: "https://updates.example/public/huge"}); w.Code != 502 {
		t.Fatal(w.Code)
	}
}
func TestPublicAddressPolicy(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.1.2.3", "169.254.169.254", "100.100.100.100", "::1", "::ffff:127.0.0.1", "fc00::1", "2001:db8::1", "64:ff9b::7f00:1"} {
		if publicIP(netip.MustParseAddr(raw)) {
			t.Fatal("private/reserved address accepted", raw)
		}
	}
	for _, raw := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		if !publicIP(netip.MustParseAddr(raw)) {
			t.Fatal(raw)
		}
	}
	if _, e := publicDial(context.Background(), "tcp", "127.0.0.1:443"); e == nil {
		t.Fatal("loopback dial accepted")
	}
	if _, e := publicDial(context.Background(), "tcp", "example.test:80"); e == nil {
		t.Fatal("port 80 accepted")
	}
}
func TestRedirectPolicy(t *testing.T) {
	g := gateway(t)
	for _, raw := range []string{"http://updates.example/public/a", "https://other.example/public/a", "https://updates.example/private/a"} {
		r := httptest.NewRequest("GET", raw, nil)
		if g.client.CheckRedirect(r, nil) == nil {
			t.Fatal(raw)
		}
	}
}

func TestOriginWithoutExplicitSlash(t *testing.T) {
	g, err := New(Config{Sources: []Source{{Origin: "https://feed.example", PathPrefix: "/"}}})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("https://feed.example")
	if !g.allowed(u) {
		t.Fatal("origin-only feed URL must mean root path")
	}
}
