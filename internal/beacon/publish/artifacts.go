package publish

import (
	"net/http"
	"os"
	"path/filepath"
	"shixpeer.com/ward/internal/distribution"
	"shixpeer.com/ward/internal/snapshot"
	"strings"
)

// Artifacts exposes only the public export directory, never the state/key dirs.
func Artifacts(dir string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if !distribution.Allowed(name) {
			http.NotFound(w, r)
			return
		}
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		info, err := f.Stat()
		if err != nil || !info.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if distribution.Binary.MatchString(name) {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-store")
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		if name == "install.sh" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		http.ServeContent(w, r, name, info.ModTime(), f)
	})
	mux.HandleFunc("GET /v1/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if name != "manifest.json" && !snapshot.ArtifactName.MatchString(name) {
			http.NotFound(w, r)
			return
		}
		f, e := os.Open(filepath.Join(dir, name))
		if e != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		info, e := f.Stat()
		if e != nil || !info.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		if name == "manifest.json" {
			w.Header().Set("Cache-Control", "no-store")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		if strings.HasSuffix(name, ".wdb") {
			w.Header().Set("Content-Type", "application/octet-stream")
		} else {
			w.Header().Set("Content-Type", "application/json")
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		http.ServeContent(w, r, name, info.ModTime(), f)
	})
	return mux
}
