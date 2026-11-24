package updategateway

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestFailureAggregationAndPrivacy(t *testing.T) {
	dir := t.TempDir()
	d, e := NewDiagnostics(dir)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/v1/update-failures", strings.NewReader(`{"bundle_id":"com.example.fixture","reason":"check_failed"}`))
		r.Header.Set("X-Forwarded-For", "192.0.2.8")
		d.ServeHTTP(w, r)
		if w.Code != 204 {
			t.Fatal(w.Code)
		}
	}
	raw, _ := os.ReadFile(d.file)
	if strings.Contains(string(raw), "192.0.2.8") {
		t.Fatal("IP retained")
	}
	var rows []Count
	if json.Unmarshal(raw, &rows) != nil || len(rows) != 1 || rows[0].Count != 2 {
		t.Fatal(string(raw))
	}
	for _, body := range []string{`{"bundle_id":"com.example.fixture","reason":"check_failed","installed":"secret"}`, `{"bundle_id":"/Users/name/App","reason":"check_failed"}`, `{"bundle_id":"com.example.fixture","reason":"free form secret"}`} {
		w := httptest.NewRecorder()
		d.ServeHTTP(w, httptest.NewRequest("POST", "/", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatal(w.Code)
		}
	}
	d.rows["old"] = Count{Failure: Failure{Bundle: "com.example.old", Reason: "check_failed"}, Day: "2000-01-01", Count: 1}
	if d.Prune() != nil {
		t.Fatal("prune")
	}
	reopened, e := NewDiagnostics(dir)
	if e != nil || len(reopened.rows) != 1 {
		t.Fatal("retention/persistence", e)
	}
	info, _ := os.Stat(d.file)
	if info.Mode().Perm() != 0600 {
		t.Fatal(info.Mode())
	}
}
func TestVersionResolverOperatorRules(t *testing.T) {
	g, _ := New(Config{Sources: []Source{{Origin: "https://feed.example", PathPrefix: "/"}}})
	g.client.Transport = roundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{"stable":[{"version":"2.4.1"}]}`))}, nil
	})
	rule := VersionRule{Bundle: "com.example.fixture", URL: "https://feed.example/releases", JSONPath: []string{"stable", "0", "version"}}
	resolver, e := NewResolver(g, []VersionRule{rule})
	if e != nil {
		t.Fatal(e)
	}
	w := httptest.NewRecorder()
	resolver.ServeHTTP(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"bundle_id":"com.example.fixture","architecture":"arm64"}`)))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "2.4.1") {
		t.Fatal(w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	resolver.ServeHTTP(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"bundle_id":"com.example.unknown","architecture":"arm64"}`)))
	if w.Code != 204 {
		t.Fatal(w.Code)
	}
	rule.URL = "https://127.0.0.1/private"
	if _, e = NewResolver(g, []VersionRule{rule}); e == nil {
		t.Fatal("unsafe rule accepted")
	}
	for _, raw := range []string{`{"stable":[]}`, `{"stable":[{"version":"<script>"}]}`} {
		rule.URL = "https://feed.example/releases"
		if _, e := extractVersion([]byte(raw), rule); e == nil {
			t.Fatal("invalid metadata accepted")
		}
	}
	version, e := extractVersion([]byte("release=3.2.1"), VersionRule{Pattern: `release=([0-9.]+)`})
	if e != nil || version != "3.2.1" {
		t.Fatal(version, e)
	}
}
