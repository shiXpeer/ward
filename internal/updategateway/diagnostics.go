package updategateway

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

var bundleID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9-]*){1,15}$`)

func validBundle(s string) bool { return len(s) <= 160 && bundleID.MatchString(s) }

type Failure struct {
	Bundle string `json:"bundle_id"`
	Reason string `json:"reason"`
}
type Count struct {
	Failure
	Day   string `json:"day"`
	Count uint64 `json:"count"`
}

// Diagnostics stores daily event counts, never requests, IPs or device IDs.
// Counts are events, not unique users. Read access is through operator SSH only.
type Diagnostics struct {
	mu   sync.Mutex
	file string
	rows map[string]Count
}

func NewDiagnostics(dir string) (*Diagnostics, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	d := &Diagnostics{file: filepath.Join(dir, "failures.json"), rows: map[string]Count{}}
	raw, err := os.ReadFile(d.file)
	if os.IsNotExist(err) {
		return d, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) > 1<<20 {
		return nil, errors.New("diagnostics exceeds limit")
	}
	var rows []Count
	if err = json.Unmarshal(raw, &rows); err != nil {
		return nil, err
	}
	if len(rows) > 2048 {
		return nil, errors.New("too many diagnostic counters")
	}
	for _, r := range rows {
		if !validBundle(r.Bundle) || !validReason(r.Reason) {
			return nil, errors.New("invalid diagnostic counter")
		}
		d.rows[r.Day+"/"+r.Bundle+"/"+r.Reason] = r
	}
	return d, nil
}
func validReason(s string) bool { return s == "unsupported_channel" || s == "check_failed" }
func decodeRequest(w http.ResponseWriter, r *http.Request, v any) bool {
	return decodeRequestLimit(w, r, v, 1024)
}
func decodeRequestLimit(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if dec.Decode(v) != nil || dec.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid request", 400)
		return false
	}
	return true
}
func (d *Diagnostics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "POST" {
		http.Error(w, "POST required", 405)
		return
	}
	var f Failure
	if !decodeRequest(w, r, &f) {
		return
	}
	if !validBundle(f.Bundle) || !validReason(f.Reason) {
		http.Error(w, "invalid category", 400)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now().UTC()
	day := now.Format("2006-01-02")
	cutoff := now.AddDate(0, 0, -30).Format("2006-01-02")
	for k, row := range d.rows {
		if row.Day < cutoff {
			delete(d.rows, k)
		}
	}
	key := day + "/" + f.Bundle + "/" + f.Reason
	row, exists := d.rows[key]
	if !exists && len(d.rows) >= 2048 {
		http.Error(w, "counter capacity reached", 429)
		return
	}
	if !exists {
		row = Count{Failure: f, Day: day}
	}
	if row.Count < 1_000_000 {
		row.Count++
	}
	d.rows[key] = row
	rows := make([]Count, 0, len(d.rows))
	for _, row := range d.rows {
		rows = append(rows, row)
	}
	raw, err := json.Marshal(rows)
	if err == nil {
		err = os.WriteFile(d.file+".next", raw, 0600)
	}
	if err == nil {
		err = os.Rename(d.file+".next", d.file)
	}
	if err != nil {
		http.Error(w, "diagnostics unavailable", 503)
		return
	}
	w.WriteHeader(204)
}

// Prune runs even when clients stop reporting, so retention is time-bounded.
func (d *Diagnostics) Prune() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	cutoff := time.Now().UTC().AddDate(0, 0, -30).Format("2006-01-02")
	rows := make([]Count, 0, len(d.rows))
	for k, row := range d.rows {
		if row.Day < cutoff {
			delete(d.rows, k)
		} else {
			rows = append(rows, row)
		}
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	if err = os.WriteFile(d.file+".next", raw, 0600); err != nil {
		return err
	}
	return os.Rename(d.file+".next", d.file)
}
