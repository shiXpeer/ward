package updategateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// VersionRule is operator-maintained public metadata, not executable code.
// JSON paths are arrays of object keys/array indices; patterns use bounded RE2.
type VersionRule struct {
	Bundle       string   `json:"bundle_id"`
	Architecture string   `json:"architecture,omitempty"`
	URL          string   `json:"url"`
	JSONPath     []string `json:"json_path,omitempty"`
	Pattern      string   `json:"pattern,omitempty"`
}
type VersionRules struct {
	Rules []VersionRule `json:"version_rules,omitempty"`
}
type Resolver struct {
	gateway *Gateway
	rules   []VersionRule
	mu      sync.Mutex
	cache   map[[32]byte]*versionCacheEntry
	slots   chan struct{}
}

func NewResolver(g *Gateway, rules []VersionRule) (*Resolver, error) {
	if len(rules) > 512 {
		return nil, errors.New("too many version rules")
	}
	seen := map[string]bool{}
	for _, r := range rules {
		u, e := url.Parse(r.URL)
		key := r.Bundle + "/" + r.Architecture
		if !validBundle(r.Bundle) || seen[key] || e != nil || !g.allowed(u) || len(r.JSONPath) > 16 || len(r.Pattern) > 512 || (r.Architecture != "" && r.Architecture != "arm64" && r.Architecture != "x86_64") {
			return nil, errors.New("invalid version rule")
		}
		seen[key] = true
		if r.Pattern != "" {
			p, e := regexp.Compile(r.Pattern)
			if e != nil || p.NumSubexp() != 1 {
				return nil, errors.New("version pattern needs one capture")
			}
		}
	}
	return &Resolver{gateway: g, rules: rules, cache: make(map[[32]byte]*versionCacheEntry), slots: make(chan struct{}, 8)}, nil
}
func (s *Resolver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "POST" {
		http.Error(w, "POST required", 405)
		return
	}
	var q VersionQuery
	if !decodeRequestLimit(w, r, &q, 12288) {
		return
	}
	if !validBundle(q.Bundle) || (q.Architecture != "arm64" && q.Architecture != "x86_64") || len(q.URL) > 3000 || len(q.URLs) > 4 {
		http.Error(w, "invalid application", 400)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		http.Error(w, "version service busy", 429)
		return
	}
	reply, err := s.cached(r, q)
	if err != nil {
		http.Error(w, "version unavailable", 502)
		return
	}
	if reply.Version == "" {
		w.WriteHeader(204)
		return
	}
	etag := versionETag(reply)
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(304)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(reply)
}

var versionValue = regexp.MustCompile(`^[0-9][A-Za-z0-9.+_-]{0,79}$`)

func extractVersion(raw []byte, r VersionRule) (string, error) {
	var text string
	if len(r.JSONPath) > 0 {
		var value any
		if json.Unmarshal(raw, &value) != nil {
			return "", errors.New("invalid JSON")
		}
		for _, key := range r.JSONPath {
			switch v := value.(type) {
			case map[string]any:
				value = v[key]
			case []any:
				i, e := strconv.Atoi(key)
				if e != nil || i < 0 || i >= len(v) {
					return "", errors.New("invalid index")
				}
				value = v[i]
			default:
				return "", errors.New("missing version")
			}
		}
		var ok bool
		text, ok = value.(string)
		if !ok {
			return "", errors.New("version must be a string")
		}
	} else {
		text = string(raw)
	}
	if r.Pattern != "" {
		m := regexp.MustCompile(r.Pattern).FindStringSubmatch(text)
		if len(m) != 2 {
			return "", errors.New("version not matched")
		}
		text = m[1]
	}
	text = strings.TrimSpace(text)
	if !versionValue.MatchString(text) {
		return "", errors.New("invalid version")
	}
	return text, nil
}

type metadataResponse struct {
	header http.Header
	Code   int
	Body   bytes.Buffer
}

func (w *metadataResponse) Header() http.Header         { return w.header }
func (w *metadataResponse) WriteHeader(code int)        { w.Code = code }
func (w *metadataResponse) Write(p []byte) (int, error) { return w.Body.Write(p) }
