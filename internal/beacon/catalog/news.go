package catalog

import (
	"context"
	"encoding/json"
	"path/filepath"
	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/internal/filelock"
	"sort"
	"strings"
)

// News is an explicit publisher-side streaming scan with bounded retained results.
// It describes upstream facts, never impact on an installed host.
func News(ctx context.Context, dir string) ([]compactdb.Row, error) {
	unlock, e := filelock.Acquire(ctx, filepath.Join(dir, "sync.lock"), true)
	if e != nil {
		return nil, e
	}
	defer unlock()
	s, e := Load(dir)
	if e != nil {
		return nil, e
	}
	out := []compactdb.Row{}
	seen := map[string]bool{}
	for _, b := range s.Buckets {
		if b.Slot[0] != 'v' && b.Slot[0] != 'r' {
			continue
		}
		f, e := compactdb.Open(b.Path)
		if e != nil {
			return nil, e
		}
		e = f.Scan(ctx, func(raw []byte) error {
			var r compactdb.Row
			if e := json.Unmarshal(raw, &r); e != nil {
				return e
			}
			if r.Withdrawn || (!r.KnownExploited && !strings.EqualFold(r.Severity, "CRITICAL")) {
				return nil
			}
			key := r.Source + "\x00" + r.ID
			if seen[key] {
				return nil
			}
			if len(out) == 200 && r.Modified < out[len(out)-1].Modified {
				return nil
			}
			out = append(out, r)
			seen[key] = true
			sort.Slice(out, func(i, j int) bool {
				if out[i].Modified != out[j].Modified {
					return out[i].Modified > out[j].Modified
				}
				return out[i].Source+out[i].ID < out[j].Source+out[j].ID
			})
			if len(out) > 200 {
				old := out[len(out)-1]
				delete(seen, old.Source+"\x00"+old.ID)
				out = out[:200]
			}
			return nil
		})
		f.Close()
		if e != nil {
			return nil, e
		}
	}
	return out, nil
}
