package updategateway

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNormalizedProtocolsAndConditionalPolling(t *testing.T) {
	signature := base64.StdEncoding.EncodeToString(make([]byte, 64))
	fixtures := map[string]string{
		"https://feed.example/sparkle":                                                    `<rss xmlns:sparkle="urn:sparkle"><channel><item><sparkle:shortVersionString>2.3.1</sparkle:shortVersionString><description>` + strings.Repeat("notes", 2000) + `</description><enclosure url="https://download.example/app.zip" sparkle:edSignature="` + signature + `" /></item></channel></rss>`,
		"https://feed.example/electron/latest-mac.yml":                                    "version: 4.2.1\npath: app.zip\n",
		"https://feed.example/plain":                                                      "3.4.2\n",
		"https://feed.example/product":                                                    "<version><number>7.1.0</number></version>",
		"https://feed.example/api/update/darwin-arm64/product/0.0.0/shixpeer-ward/stable": `{"name":"9.2.1","url":"https://download.example/app.zip"}`,
	}
	g, _ := New(Config{Sources: []Source{{Origin: "https://feed.example", PathPrefix: "/"}}})
	calls := 0
	g.client.Transport = roundTrip(func(r *http.Request) (*http.Response, error) {
		calls++
		body, ok := fixtures[r.URL.String()]
		if !ok {
			t.Fatal("unexpected upstream", r.URL)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}, nil
	})
	s, _ := NewResolver(g, nil)
	for _, tc := range []struct {
		channel, path, version string
		install                bool
	}{{"sparkle", "sparkle", "2.3.1", true}, {"electron", "electron", "4.2.1", true}, {"plain", "plain", "3.4.2", false}, {"product_xml", "product", "7.1.0", false}, {"vscode", "", "9.2.1", true}} {
		q := VersionQuery{Bundle: "com.example.fixture", Architecture: "arm64", Channel: tc.channel, URL: "https://feed.example/" + tc.path, Platform: "darwin-arm64", Name: "product", Quality: "stable"}
		got, e := s.resolve(httptest.NewRequest("POST", "/", nil), q)
		if e != nil || got.Version != tc.version || got.Installable != tc.install {
			t.Fatal(tc.channel, got, e)
		}
	}
	body := `{"bundle_id":"com.example.fixture","architecture":"arm64","channel":"plain","url":"https://feed.example/plain"}`
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("POST", "/", strings.NewReader(body)))
	before := calls
	r := httptest.NewRequest("POST", "/", strings.NewReader(body))
	r.Header.Set("If-None-Match", w.Header().Get("ETag"))
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 304 || calls != before {
		t.Fatal("conditional polling re-fetched upstream", w.Code, calls, before)
	}
	for _, bad := range []string{`<!DOCTYPE rss [<!ENTITY x "secret">]><rss/>`, `<rss><item>`} {
		if _, e := xmlVersion([]byte(bad), "sparkle"); e == nil {
			t.Fatal("bad XML accepted")
		}
	}
}
