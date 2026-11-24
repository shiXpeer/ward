package updategateway

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Homebrew preserves the original signed API bytes. Bottles/source archives
// are not mirrored; Homebrew continues to verify its JWS and artifact hashes.
type Homebrew struct {
	dir    string
	client *http.Client
	mu     sync.Mutex
	slots  chan struct{}
}

var brewPath = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./@+-]{0,180}\.(json|txt)$`)

const brewLimit = 64 << 20

func NewHomebrew(dir string) (*Homebrew, error) {
	if dir == "" {
		return nil, errors.New("Homebrew metadata cache directory required")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = publicDial
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	return &Homebrew{dir: dir, slots: make(chan struct{}, 4), client: &http.Client{Transport: tr, Timeout: 60 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) >= 3 || !validURL(r.URL) || r.URL.Hostname() != "formulae.brew.sh" {
			return errors.New("unapproved Homebrew metadata redirect")
		}
		return nil
	}}}, nil
}
func (h *Homebrew) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Method != "GET" && r.Method != "HEAD" {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "GET required", 405)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/v1/homebrew/")
	if !brewPath.MatchString(name) || path.Clean(name) != name || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		http.Error(w, "metadata service busy", 429)
		return
	}
	hash := sha256.Sum256([]byte(name))
	target := filepath.Join(h.dir, hex.EncodeToString(hash[:]))
	h.mu.Lock()
	info, e := os.Stat(target)
	if e != nil || time.Since(info.ModTime()) > 10*time.Minute {
		e = h.fetch(r, "https://formulae.brew.sh/api/"+name, target)
	}
	h.mu.Unlock()
	if e != nil {
		http.Error(w, "Homebrew metadata unavailable", 502)
		return
	}
	file, e := os.Open(target)
	if e != nil {
		http.Error(w, "metadata unavailable", 503)
		return
	}
	defer file.Close()
	info, e = file.Stat()
	if e != nil {
		http.Error(w, "metadata unavailable", 503)
		return
	}
	if strings.HasSuffix(name, ".json") {
		w.Header().Set("Content-Type", "application/json")
	} else {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	http.ServeContent(w, r, name, info.ModTime(), file)
}
func (h *Homebrew) fetch(r *http.Request, raw, target string) error {
	u, e := url.Parse(raw)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(r.Context(), "GET", u.String(), nil)
	if e != nil {
		return e
	}
	req.Header.Set("User-Agent", "shixpeer-ward-homebrew-metadata")
	resp, e := h.client.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.ContentLength > brewLimit {
		return errors.New("invalid Homebrew metadata response")
	}
	file, e := os.CreateTemp(h.dir, ".next-")
	if e != nil {
		return e
	}
	defer os.Remove(file.Name())
	n, e := io.Copy(file, io.LimitReader(resp.Body, brewLimit+1))
	closeErr := file.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if n == 0 || n > brewLimit {
		return errors.New("Homebrew metadata too large or empty")
	}
	if e = os.Rename(file.Name(), target); e != nil {
		return e
	}
	entries, e := os.ReadDir(h.dir)
	if e != nil {
		return e
	}
	type item struct {
		name  string
		size  int64
		mtime time.Time
	}
	files := []item{}
	var total int64
	for _, v := range entries {
		if i, e := v.Info(); e == nil && i.Mode().IsRegular() {
			files = append(files, item{v.Name(), i.Size(), i.ModTime()})
			total += i.Size()
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].mtime.Before(files[j].mtime) })
	count := len(files)
	for _, v := range files {
		if count <= 64 && total <= 512<<20 {
			break
		}
		p := filepath.Join(h.dir, v.name)
		if p != target {
			if os.Remove(p) == nil {
				total -= v.size
				count--
			}
		}
	}
	return nil
}
