package publish

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestOnlyPublicArtifacts(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "signing.key"), []byte("SECRET"), 0600)
	h := Artifacts(dir)
	for _, path := range []string{"/v1/signing.key", "/v1/feed", "/v1/feed.json", "/v1/"} {
		r := httptest.NewRecorder()
		h.ServeHTTP(r, httptest.NewRequest(http.MethodGet, path, nil))
		if r.Code != 404 {
			t.Fatal(path, r.Code)
		}
	}
}
