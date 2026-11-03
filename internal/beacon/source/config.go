package source

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"shixpeer.com/ward/internal/netpolicy"
	"shixpeer.com/ward/pkg/vuln"
	"strings"
	"time"
)

type Definition struct {
	RecordKinds  []string `json:"record_kinds,omitempty"`
	ID           string   `json:"id"`
	Type         string   `json:"type"`
	URL          string   `json:"url,omitempty"`
	Path         string   `json:"path,omitempty"`
	CAFile       string   `json:"ca_file,omitempty"`
	Enabled      bool     `json:"enabled"`
	MaxBytes     int64    `json:"max_bytes,omitempty"`
	AllowedHosts []string `json:"allowed_hosts,omitempty"`
}
type Config struct {
	Sources []Definition `json:"sources"`
}

func Load(path string) ([]Source, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	body, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if e != nil {
		return nil, e
	}
	if len(body) > 1<<20 {
		return nil, errors.New("source config exceeds 1 MiB")
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var cfg Config
	if e = dec.Decode(&cfg); e != nil {
		return nil, e
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, errors.New("source config must contain one JSON document")
	}
	var sources []Source
	seen := map[string]bool{}
	for _, d := range cfg.Sources {
		if !d.Enabled {
			continue
		}
		if d.ID == "" || seen[d.ID] {
			return nil, errors.New("source IDs must be nonempty and unique")
		}
		seen[d.ID] = true
		if d.Type != "osv" && d.Type != "osv-zip" && d.Type != "cisa-kev" && d.Type != "osv-tar-xz" && d.Type != "debian-tracker" && d.Type != "sofa" && d.Type != "epss-gzip" && d.Type != "nvd-gzip" && d.Type != "apple-security" && d.Type != "nvd-years" && d.Type != "cve-tar-gzip" && d.Type != "ghsa-tar-gzip" {
			return nil, fmt.Errorf("source %s: unsupported adapter %q", d.ID, d.Type)
		}
		if (d.Path == "") == (d.URL == "") {
			return nil, errors.New("choose exactly one source path or URL")
		}
		if d.Path != "" && !filepath.IsAbs(d.Path) {
			d.Path = filepath.Join(filepath.Dir(path), d.Path)
		}
		if d.CAFile != "" && !filepath.IsAbs(d.CAFile) {
			d.CAFile = filepath.Join(filepath.Dir(path), d.CAFile)
		}
		for _, kind := range d.RecordKinds {
			if d.Type != "osv-tar-xz" || (kind != "cve" && kind != "usn" && kind != "lsn") {
				return nil, errors.New("record_kinds only supports Canonical cve/usn/lsn")
			}
		}
		if d.MaxBytes == 0 {
			d.MaxBytes = 64 << 20
		}
		if d.MaxBytes < 1 || d.MaxBytes > 512<<20 {
			return nil, errors.New("source size limit must be 1..512 MiB")
		}
		if d.URL != "" {
			u, e := url.Parse(d.URL)
			if e != nil {
				return nil, errors.New("invalid source URL")
			}
			d.AllowedHosts = append(d.AllowedHosts, u.Hostname())
			if e = netpolicy.URL(d.URL, d.AllowedHosts); e != nil {
				return nil, e
			}
		}
		sources = append(sources, &documentSource{definition: d})
	}
	return sources, nil
}

type documentSource struct{ definition Definition }

func (s *documentSource) ID() string { return s.definition.ID }
func (s *documentSource) Sync(ctx context.Context, _ string) (Batch, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	d := s.definition
	if d.Type == "nvd-years" {
		return s.syncNVDYears(ctx)
	}
	if d.Type == "apple-security" {
		b, e := s.syncApple(ctx)
		if e == nil {
			b.FetchedAt = time.Now().UTC()
		}
		return b, e
	}
	var reader io.ReadCloser
	if d.Path != "" {
		f, e := os.Open(d.Path)
		if e != nil {
			return Batch{}, e
		}
		reader = f
	} else {
		c, e := netpolicy.Client(d.CAFile, d.AllowedHosts)
		if e != nil {
			return Batch{}, e
		}
		c.Timeout = 20 * time.Minute
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, d.URL, nil)
		if e != nil {
			return Batch{}, e
		}
		req.Header.Set("Accept", "application/json, application/zip, application/gzip, application/x-xz")
		req.Header.Set("User-Agent", "shixpeer-ward-beacon (+https://shixpeer.com)")
		resp, e := c.Do(req)
		if e != nil {
			return Batch{}, errors.New("source request failed")
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return Batch{}, errors.New("source returned non-200 status")
		}
		reader = resp.Body
	}
	defer reader.Close()
	if d.Type == "osv-tar-xz" || d.Type == "debian-tracker" || d.Type == "sofa" || d.Type == "epss-gzip" || d.Type == "nvd-gzip" || d.Type == "cve-tar-gzip" || d.Type == "ghsa-tar-gzip" {
		bounded := &checkedReader{ctx: ctx, r: reader, left: d.MaxBytes}
		var e error
		var input io.Reader = bounded
		if d.Type == "epss-gzip" || d.Type == "nvd-gzip" {
			input, e = gzipReader(ctx, bounded)
			if e != nil {
				return Batch{}, e
			}
		}
		var adv []Advisory
		switch d.Type {
		case "cve-tar-gzip", "ghsa-tar-gzip":
			adv, e = parseRepository(ctx, input, d.Type)
		case "osv-tar-xz":
			adv, e = parseOSVTarKinds(ctx, input, d.RecordKinds)
		case "debian-tracker":
			adv, e = parseDebian(ctx, input)
		case "sofa":
			adv, e = parseSOFA(input)
		case "epss-gzip":
			adv, e = parseEPSS(input)
		case "nvd-gzip":
			adv, e = parseNVD(ctx, input)
		}
		if e != nil {
			return Batch{}, e
		}
		if _, e = io.Copy(io.Discard, input); e != nil {
			return Batch{}, e
		}
		return Batch{Full: true, FetchedAt: time.Now().UTC(), Advisories: adv}, nil
	}
	body, e := io.ReadAll(io.LimitReader(reader, d.MaxBytes+1))
	if e != nil {
		return Batch{}, e
	}
	if int64(len(body)) > d.MaxBytes {
		return Batch{}, errors.New("source exceeds compressed/input byte limit")
	}
	var adv []Advisory
	switch d.Type {
	case "osv":
		adv, e = parseOSVDocument(body)
	case "osv-zip":
		adv, e = parseOSVZip(ctx, body)
	case "cisa-kev":
		adv, e = parseKEV(body)
	}
	if e != nil {
		return Batch{}, e
	}
	return Batch{Full: true, FetchedAt: time.Now().UTC(), Advisories: adv}, nil
}

type osv struct {
	ID               string     `json:"id"`
	Aliases          []string   `json:"aliases"`
	Upstream         []string   `json:"upstream"`
	Related          []string   `json:"related"`
	Summary          string     `json:"summary"`
	Details          string     `json:"details"`
	Published        time.Time  `json:"published"`
	Modified         time.Time  `json:"modified"`
	Withdrawn        *time.Time `json:"withdrawn"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges            []vuln.Range    `json:"ranges"`
		Versions          []string        `json:"versions"`
		EcosystemSpecific json.RawMessage `json:"ecosystem_specific"`
		DatabaseSpecific  json.RawMessage `json:"database_specific"`
	} `json:"affected"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

func parseOSV(raw json.RawMessage) (Advisory, error) {
	var o osv
	if e := json.Unmarshal(raw, &o); e != nil {
		return Advisory{}, e
	}
	if o.ID == "" || o.Modified.IsZero() {
		return Advisory{}, errors.New("OSV record requires id and modified")
	}
	for _, id := range o.Upstream {
		if cveID.MatchString(id) {
			o.Aliases = append(o.Aliases, id)
		}
	}
	a := Advisory{ID: o.ID, Aliases: o.Aliases, Summary: o.Summary, Severity: o.DatabaseSpecific.Severity, Published: o.Published, Modified: o.Modified, Withdrawn: o.Withdrawn != nil, Raw: append(json.RawMessage(nil), raw...)}
	for _, p := range o.Affected {
		if p.Package.Name == "" || p.Package.Ecosystem == "" {
			a.UnmappedAffected++
			continue
		}
		a.Affected = append(a.Affected, Affected{Ecosystem: p.Package.Ecosystem, Name: p.Package.Name, Ranges: p.Ranges, Versions: p.Versions, EcosystemSpecific: p.EcosystemSpecific, DatabaseSpecific: p.DatabaseSpecific})
	}
	for _, r := range o.References {
		if safeReference(r.URL) {
			a.References = append(a.References, r.URL)
		}
	}
	return a, nil
}
func safeReference(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil
}
func parseOSVDocument(b []byte) ([]Advisory, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 {
		return nil, errors.New("empty source document")
	}
	var rows []json.RawMessage
	if b[0] == '[' {
		if e := json.Unmarshal(b, &rows); e != nil {
			return nil, e
		}
	} else {
		var wrapper struct {
			Vulns []json.RawMessage `json:"vulns"`
		}
		if e := json.Unmarshal(b, &wrapper); e != nil {
			return nil, e
		}
		if wrapper.Vulns != nil {
			rows = wrapper.Vulns
		} else {
			rows = []json.RawMessage{b}
		}
	}
	if len(rows) > maxRecords {
		return nil, errors.New("source record count exceeds limit")
	}
	out := make([]Advisory, 0, len(rows))
	seen := map[string]bool{}
	for _, row := range rows {
		a, e := parseOSV(row)
		if e != nil {
			return nil, e
		}
		if seen[a.ID] {
			return nil, errors.New("duplicate OSV advisory ID in snapshot")
		}
		seen[a.ID] = true
		out = append(out, a)
	}
	return out, nil
}
func parseOSVZip(ctx context.Context, b []byte) ([]Advisory, error) {
	z, e := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if e != nil {
		return nil, e
	}
	var out []Advisory
	total := int64(0)
	seen := map[string]bool{}
	for _, f := range z.File {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		if f.FileInfo().IsDir() || !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		if f.UncompressedSize64 > 8<<20 {
			return nil, errors.New("OSV archive entry exceeds 8 MiB")
		}
		r, e := f.Open()
		if e != nil {
			return nil, e
		}
		raw, e := io.ReadAll(io.LimitReader(r, 8<<20+1))
		r.Close()
		if e != nil {
			return nil, e
		}
		total += int64(len(raw))
		if len(raw) > 8<<20 || total > maxStream {
			return nil, errors.New("OSV archive expansion limit exceeded")
		}
		a, e := parseOSV(raw)
		if e != nil {
			return nil, e
		}
		if seen[a.ID] {
			return nil, errors.New("duplicate OSV advisory ID in archive")
		}
		seen[a.ID] = true
		out = append(out, a)
		if len(out) > maxRecords {
			return nil, errors.New("OSV archive record limit exceeded")
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no OSV JSON records in archive")
	}
	return out, nil
}
func parseKEV(b []byte) ([]Advisory, error) {
	var doc struct {
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	}
	if e := json.Unmarshal(b, &doc); e != nil {
		return nil, e
	}
	if doc.Vulnerabilities == nil {
		return nil, errors.New("missing KEV vulnerabilities array")
	}
	out := make([]Advisory, 0, len(doc.Vulnerabilities))
	seen := map[string]bool{}
	for _, raw := range doc.Vulnerabilities {
		var row struct {
			ID          string `json:"cveID"`
			Name        string `json:"vulnerabilityName"`
			Date        string `json:"dateAdded"`
			Description string `json:"shortDescription"`
			Action      string `json:"requiredAction"`
		}
		if e := json.Unmarshal(raw, &row); e != nil {
			return nil, e
		}
		if !strings.HasPrefix(row.ID, "CVE-") || seen[row.ID] {
			return nil, errors.New("invalid or duplicate KEV CVE ID")
		}
		seen[row.ID] = true
		at, e := time.Parse("2006-01-02", row.Date)
		if e != nil {
			return nil, e
		}
		out = append(out, Advisory{ID: row.ID, Summary: row.Name, Modified: at, KnownExploited: true, ExploitedAt: at, Raw: raw, References: []string{"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}})
	}
	return out, nil
}
