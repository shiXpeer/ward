package updategateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestHomebrewMirrorPreservesSignedBytes(t *testing.T) {
	h, e := NewHomebrew(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	calls := 0
	body := `{"payload":"signed-original","signatures":[{"signature":"unchanged"}]}`
	h.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.String() != "https://formulae.brew.sh/api/internal/packages.arm64_fixture.jws.json" {
			t.Fatal(r.URL)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
	})
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/v1/homebrew/internal/packages.arm64_fixture.jws.json", nil))
		if w.Code != 200 || w.Body.String() != body {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if calls != 1 {
		t.Fatal("mirror not cached")
	}
}
func TestHomebrewRejectsTraversalAndArchives(t *testing.T) {
	h, _ := NewHomebrew(t.TempDir())
	h.client.Transport = roundTrip(func(*http.Request) (*http.Response, error) { t.Fatal("unapproved fetch"); return nil, nil })
	for _, p := range []string{"/v1/homebrew/../secret.json", "/v1/homebrew/file.tar.gz", "/v1/homebrew/file.json?url=https://127.0.0.1", "/v1/homebrew/https://evil.example/feed.json"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", p, nil))
		if w.Code != 404 {
			t.Fatal(p, w.Code)
		}
	}
}
func TestHomebrewFailureDoesNotBecomeEmptyCatalog(t *testing.T) {
	dir := t.TempDir()
	h, _ := NewHomebrew(dir)
	h.client.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("upstream error")), Header: http.Header{}}, nil
	})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/v1/homebrew/formula.jws.json", nil))
	if w.Code != 502 {
		t.Fatal(w.Code)
	}
	files, _ := os.ReadDir(dir)
	if len(files) != 0 {
		t.Fatal("failed response cached")
	}
}
