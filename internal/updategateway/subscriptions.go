package updategateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"
)

type versionCacheEntry struct {
	query             VersionQuery
	reply             VersionReply
	err               error
	checked, lastSeen time.Time
	ready             chan struct{}
}

// The cache tracks public update channels, not clients/subscribers. It is bounded
// and expires inactive channels after 24h. No IP/device/session identifier exists.
func (s *Resolver) cached(r *http.Request, q VersionQuery) (VersionReply, error) {
	raw, _ := json.Marshal(q)
	key := sha256.Sum256(raw)
	now := time.Now()
	s.mu.Lock()
	if e := s.cache[key]; e != nil {
		e.lastSeen = now
		if e.ready != nil {
			ready := e.ready
			s.mu.Unlock()
			select {
			case <-ready:
				return s.cached(r, q)
			case <-r.Context().Done():
				return VersionReply{}, r.Context().Err()
			}
		}
		ttl := 15 * time.Minute
		if e.err != nil {
			ttl = time.Minute
		}
		if now.Sub(e.checked) < ttl {
			reply, err := e.reply, e.err
			s.mu.Unlock()
			return reply, err
		}
	}
	if len(s.cache) >= 512 {
		for k, e := range s.cache {
			if e.ready == nil {
				delete(s.cache, k)
				break
			}
		}
	}
	entry := &versionCacheEntry{query: q, lastSeen: now, ready: make(chan struct{})}
	s.cache[key] = entry
	s.mu.Unlock()
	reply, err := s.resolve(r, q)
	s.mu.Lock()
	entry.reply = reply
	entry.err = err
	entry.checked = time.Now()
	close(entry.ready)
	entry.ready = nil
	s.mu.Unlock()
	return reply, err
}
func (s *Resolver) Refresh(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.mu.Lock()
			queries := []VersionQuery{}
			for key, e := range s.cache {
				if now.Sub(e.lastSeen) > 24*time.Hour && e.ready == nil {
					delete(s.cache, key)
				} else if e.ready == nil {
					queries = append(queries, e.query)
				}
			}
			s.mu.Unlock()
			for _, q := range queries {
				if ctx.Err() != nil {
					return
				}
				work, cancel := context.WithTimeout(ctx, 30*time.Second)
				r, _ := http.NewRequestWithContext(work, "POST", "https://ward.internal/v1/app-version", nil)
				// Resolve directly: background work must not extend a subscription's lastSeen.
				reply, err := s.resolve(r, q)
				cancel()
				raw, _ := json.Marshal(q)
				key := sha256.Sum256(raw)
				s.mu.Lock()
				if e := s.cache[key]; e != nil && e.ready == nil {
					e.reply = reply
					e.err = err
					e.checked = time.Now()
				}
				s.mu.Unlock()
			}
		}
	}
}
func versionETag(reply VersionReply) string {
	b, _ := json.Marshal(reply)
	sum := sha256.Sum256(b)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}
