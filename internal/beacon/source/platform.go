package source

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"regexp"
	"shixpeer.com/ward/internal/cpe"
	"shixpeer.com/ward/internal/netpolicy"
	"shixpeer.com/ward/internal/productid"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ulikunitz/xz"
	"shixpeer.com/ward/internal/evidence"
	"shixpeer.com/ward/pkg/vuln"
)

const maxRecords = 1500000
const maxEntry = 8 << 20
const maxStream = int64(16 << 30)

var cveID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

// checkedReader bounds decompression and checks cancellation between reads.
type checkedReader struct {
	ctx  context.Context
	r    io.Reader
	left int64
}

func (r *checkedReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	if r.left <= 0 {
		var b [1]byte
		n, e := r.r.Read(b[:])
		if n > 0 {
			return 0, errors.New("expanded source limit exceeded")
		}
		return 0, e
	}
	if int64(len(p)) > r.left {
		p = p[:r.left]
	}
	n, e := r.r.Read(p)
	r.left -= int64(n)
	return n, e
}
func compact(raw []byte) json.RawMessage {
	var b bytes.Buffer
	if json.Compact(&b, raw) != nil {
		return nil
	}
	return b.Bytes()
}
func parseTime(s string) time.Time {
	for _, f := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999", "2006-01-02T15:04:05", "2006-01-02"} {
		if t, e := time.Parse(f, s); e == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
func validRows(a []Advisory, e error) ([]Advisory, error) {
	if e != nil {
		return nil, e
	}
	if len(a) == 0 {
		return nil, errors.New("source contains no advisories")
	}
	if len(a) > maxRecords {
		return nil, errors.New("source record limit exceeded")
	}
	return a, nil
}

func parseOSVTar(ctx context.Context, r io.Reader) ([]Advisory, error) {
	return parseOSVTarKinds(ctx, r, nil)
}
func parseOSVTarKinds(ctx context.Context, r io.Reader, kinds []string) ([]Advisory, error) {
	// Cap decoder dictionary independently of compressed and expanded byte limits.
	xr, e := (xz.ReaderConfig{DictCap: 64 << 20}).NewReader(r)
	if e != nil {
		return nil, e
	}
	bounded := &checkedReader{ctx: ctx, r: xr, left: maxStream}
	tr := tar.NewReader(bounded)
	out := []Advisory{}
	seen := map[string]bool{}
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		if h.Typeflag != tar.TypeReg || !strings.HasSuffix(h.Name, ".json") {
			continue
		}
		if len(kinds) > 0 {
			selected := false
			for _, kind := range kinds {
				if strings.HasPrefix(h.Name, "osv/"+kind+"/") {
					selected = true
					break
				}
			}
			if !selected {
				continue
			}
		}
		if h.Size < 1 || h.Size > maxEntry {
			return nil, errors.New("OSV tar entry limit exceeded")
		}
		b, e := io.ReadAll(io.LimitReader(tr, maxEntry+1))
		if e != nil {
			return nil, e
		}
		a, e := parseOSV(compact(b))
		if e != nil {
			return nil, fmt.Errorf("OSV tar record: %w", e)
		}
		a.Raw, e = evidence.Pack(a.Raw)
		if e != nil {
			return nil, e
		}
		for i := range a.Affected {
			p := &a.Affected[i]
			if len(p.EcosystemSpecific) > 0 {
				p.EcosystemSpecific, e = evidence.Pack(p.EcosystemSpecific)
				if e != nil {
					return nil, e
				}
			}
			if len(p.DatabaseSpecific) > 0 {
				p.DatabaseSpecific, e = evidence.Pack(p.DatabaseSpecific)
				if e != nil {
					return nil, e
				}
			}
		}
		if seen[a.ID] {
			return nil, errors.New("duplicate OSV tar ID")
		}
		seen[a.ID] = true
		out = append(out, a)
		if len(out) > maxRecords {
			return nil, errors.New("OSV tar record limit exceeded")
		}
	}
	// Consume the xz footer too: corruption after tar EOF is still a failed sync.
	if _, e = io.Copy(io.Discard, bounded); e != nil {
		return nil, e
	}
	return validRows(out, nil)
}

func parseDebian(ctx context.Context, r io.Reader) ([]Advisory, error) {
	d := json.NewDecoder(r)
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return nil, errors.New("Debian tracker must be an object")
	}
	out := []Advisory{}
	for d.More() {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		name, e := d.Token()
		if e != nil {
			return nil, e
		}
		pkg := name.(string)
		var issues map[string]json.RawMessage
		if e = d.Decode(&issues); e != nil {
			return nil, e
		}
		keys := make([]string, 0, len(issues))
		for k := range issues {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, id := range keys {
			if !cveID.MatchString(id) {
				continue
			}
			raw := issues[id]
			var item struct {
				Description string                     `json:"description"`
				Releases    map[string]json.RawMessage `json:"releases"`
			}
			if e = json.Unmarshal(raw, &item); e != nil {
				return nil, e
			}
			a := Advisory{ID: "DEBIAN-" + id + ":" + pkg, Aliases: []string{id}, Summary: item.Description}
			// Tracker has no trustworthy publication/modified timestamp: leave it unknown.
			evidence, _ := json.Marshal(map[string]any{"source_package": pkg, "tracker": json.RawMessage(raw)})
			a.Raw = evidence
			rels := make([]string, 0, len(item.Releases))
			for release := range item.Releases {
				rels = append(rels, release)
			}
			sort.Strings(rels)
			for _, release := range rels {
				data := item.Releases[release]
				var v struct {
					Status string `json:"status"`
					Fixed  string `json:"fixed_version"`
				}
				if e = json.Unmarshal(data, &v); e != nil {
					return nil, e
				}
				// fixed_version=0 means not affected. Never manufacture an affected range for it.
				p := Affected{Ecosystem: "Debian:" + release, Name: pkg, EcosystemSpecific: compact(data)}
				if v.Fixed != "" && v.Fixed != "0" {
					p.Ranges = []vuln.Range{{Type: "ECOSYSTEM", Events: []vuln.RangeEvent{{Introduced: "0"}, {Fixed: v.Fixed}}}}
				}
				a.Affected = append(a.Affected, p)
			}
			out = append(out, a)
			if len(out) > maxRecords {
				return nil, errors.New("Debian record limit exceeded")
			}
		}
	}
	if _, e = d.Token(); e != nil {
		return nil, e
	}
	if e = finishJSON(d); e != nil {
		return nil, e
	}
	return validRows(out, nil)
}
func finishJSON(d interface{ Decode(any) error }) error {
	var v any
	if e := d.Decode(&v); e != io.EOF {
		return errors.New("trailing or invalid JSON")
	}
	return nil
}

func parseSOFA(r io.Reader) ([]Advisory, error) {
	var doc struct {
		OSVersions []struct {
			OSVersion        string
			SecurityReleases []json.RawMessage
		}
	}
	d := json.NewDecoder(r)
	if e := d.Decode(&doc); e != nil {
		return nil, e
	}
	if e := finishJSON(d); e != nil {
		return nil, e
	}
	out := []Advisory{}
	seen := map[string]bool{}
	for _, os := range doc.OSVersions {
		for _, raw := range os.SecurityReleases {
			var s struct {
				ProductVersion, ProductName, ReleaseDate, SecurityInfo, Build string
				CVEs                                                          map[string]bool
			}
			if e := json.Unmarshal(raw, &s); e != nil {
				return nil, e
			}
			if s.ProductVersion == "" || parseTime(s.ReleaseDate).IsZero() {
				return nil, errors.New("SOFA release requires version and date")
			}
			ids := make([]string, 0, len(s.CVEs))
			for id := range s.CVEs {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			for _, id := range ids {
				if !cveID.MatchString(id) {
					return nil, errors.New("invalid SOFA CVE")
				}
				key := "SOFA-" + id + ":" + os.OSVersion + ":" + s.ProductVersion + ":" + s.Build
				if seen[key] {
					return nil, errors.New("duplicate SOFA release/CVE")
				}
				seen[key] = true
				// A fix in one branch is not proof every older macOS branch is affected.
				meta, _ := json.Marshal(map[string]any{"os_branch": os.OSVersion, "fixed_version": s.ProductVersion, "build": s.Build, "applicability": "vendor-bulletin-review-required"})
				a := Advisory{ID: key, Aliases: []string{id}, Summary: fmt.Sprintf("%s: security release %s", os.OSVersion, s.ProductVersion), Modified: parseTime(s.ReleaseDate), Raw: compact(raw), Affected: []Affected{{Ecosystem: "macOS", Name: "macOS", EcosystemSpecific: meta}}}
				if safeReference(s.SecurityInfo) {
					a.References = []string{s.SecurityInfo}
				}
				out = append(out, a)
			}
		}
	}
	return validRows(out, nil)
}

func parseEPSS(r io.Reader) ([]Advisory, error) {
	br := bufio.NewReader(r)
	first, e := br.ReadString('\n')
	if e != nil {
		return nil, e
	}
	if !strings.HasPrefix(first, "#") {
		return nil, errors.New("EPSS model/date metadata required")
	}
	var date time.Time
	for _, field := range strings.Split(strings.TrimSpace(strings.TrimPrefix(first, "#")), ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(field), ":")
		if ok && k == "score_date" {
			date = parseTime(v)
		}
	}
	if date.IsZero() {
		return nil, errors.New("EPSS score_date required")
	}
	cr := csv.NewReader(br)
	cr.Comment = '#'
	head, e := cr.Read()
	if e != nil {
		return nil, e
	}
	if strings.Join(head, ",") != "cve,epss,percentile" {
		return nil, errors.New("unexpected EPSS CSV columns")
	}
	out := []Advisory{}
	seen := map[string]bool{}
	for {
		row, e := cr.Read()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, e
		}
		if len(row) != 3 || !cveID.MatchString(row[0]) || seen[row[0]] {
			return nil, errors.New("invalid or duplicate EPSS CVE")
		}
		seen[row[0]] = true
		p, e := strconv.ParseFloat(row[1], 64)
		if e != nil || math.IsNaN(p) || p < 0 || p > 1 {
			return nil, errors.New("invalid EPSS score")
		}
		q, e := strconv.ParseFloat(row[2], 64)
		if e != nil || math.IsNaN(q) || q < 0 || q > 1 {
			return nil, errors.New("invalid EPSS percentile")
		}
		raw, _ := json.Marshal(map[string]any{"cve": row[0], "epss": p, "percentile": q, "score_date": date.Format("2006-01-02"), "metadata": strings.TrimSpace(first)})
		out = append(out, Advisory{ID: row[0], Modified: date, Raw: raw, Summary: "EPSS exploitation probability"})
		if len(out) > maxRecords {
			return nil, errors.New("EPSS record limit exceeded")
		}
	}
	return validRows(out, nil)
}

func gzipReader(ctx context.Context, r io.Reader) (io.Reader, error) {
	g, e := gzip.NewReader(r)
	if e != nil {
		return nil, e
	}
	return &checkedReader{ctx: ctx, r: g, left: maxStream}, nil
}
func parseNVD(ctx context.Context, r io.Reader) ([]Advisory, error) {
	d := json.NewDecoder(r)
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return nil, errors.New("invalid NVD object")
	}
	out := []Advisory{}
	found := false
	seen := map[string]bool{}
	for d.More() {
		key, e := d.Token()
		if e != nil {
			return nil, e
		}
		if key != "vulnerabilities" {
			var skip json.RawMessage
			if e = d.Decode(&skip); e != nil {
				return nil, e
			}
			continue
		}
		if found {
			return nil, errors.New("duplicate NVD array")
		}
		found = true
		t, e = d.Token()
		if e != nil || t != json.Delim('[') {
			return nil, errors.New("invalid NVD array")
		}
		for d.More() {
			if e = ctx.Err(); e != nil {
				return nil, e
			}
			var row struct {
				CVE json.RawMessage `json:"cve"`
			}
			if e = d.Decode(&row); e != nil {
				return nil, e
			}
			a, e := parseNVDRecord(row.CVE)
			if e != nil {
				return nil, e
			}
			if seen[a.ID] {
				return nil, errors.New("duplicate NVD CVE")
			}
			seen[a.ID] = true
			out = append(out, a)
			if len(out) > maxRecords {
				return nil, errors.New("NVD record limit exceeded")
			}
		}
		if _, e = d.Token(); e != nil {
			return nil, e
		}
	}
	if _, e = d.Token(); e != nil {
		return nil, e
	}
	if e = finishJSON(d); e != nil {
		return nil, e
	}
	if !found {
		return nil, errors.New("missing NVD vulnerabilities")
	}
	return validRows(out, nil)
}
func parseNVDRecord(raw json.RawMessage) (Advisory, error) {
	var c struct {
		ID, Published, LastModified, VulnStatus string
		Descriptions                            []struct{ Lang, Value string }
		References                              []struct{ URL string }
		Metrics                                 map[string][]struct {
			Type     string
			CVSSData struct{ BaseSeverity string }
		}
		Configurations json.RawMessage
	}
	if e := json.Unmarshal(raw, &c); e != nil {
		return Advisory{}, e
	}
	if !cveID.MatchString(c.ID) || parseTime(c.LastModified).IsZero() {
		return Advisory{}, errors.New("NVD requires valid CVE and modified")
	}
	a := Advisory{ID: c.ID, Published: parseTime(c.Published), Modified: parseTime(c.LastModified), Withdrawn: strings.EqualFold(c.VulnStatus, "Rejected"), Raw: compact(raw)}
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			a.Summary = d.Value
			break
		}
	}
	for _, version := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
		for _, m := range c.Metrics[version] {
			if a.Severity == "" || m.Type == "Primary" {
				a.Severity = m.CVSSData.BaseSeverity
			}
			if m.Type == "Primary" {
				break
			}
		}
		if a.Severity != "" {
			break
		}
	}
	for _, ref := range c.References {
		if safeReference(ref.URL) {
			a.References = append(a.References, ref.URL)
		}
	}
	// Index only explicitly mapped products; preserve the leaf and whether the
	// original tree imposed additional conditions. Raw trees remain available.
	if len(c.Configurations) > 0 {
		rules, err := cpe.Extract(c.Configurations)
		if err != nil {
			a.UnmappedAffected++
			return a, nil
		}
		for _, rule := range rules {
			name, err := cpe.Parse(rule.Match.Criteria)
			if err != nil || !productid.Known(name.Key()) {
				a.UnmappedAffected++
				continue
			}
			meta, _ := json.Marshal(rule)
			a.Affected = append(a.Affected, Affected{Ecosystem: "CPE", Name: name.Key(), EcosystemSpecific: json.RawMessage(`{"applicability":"nvd-cpe-v1"}`), DatabaseSpecific: meta})
		}
	}
	return a, nil
}

// syncNVDYears bootstraps every annual file, including the pre-2002 baseline.
// Years are generated locally; no inventory or vulnerability query is transmitted.
func (s *documentSource) syncNVDYears(ctx context.Context) (Batch, error) {
	d := s.definition
	if d.URL == "" || !strings.HasSuffix(d.URL, "/") {
		return Batch{}, errors.New("NVD annual source requires HTTPS directory URL")
	}
	c, e := netpolicy.Client(d.CAFile, d.AllowedHosts)
	if e != nil {
		return Batch{}, e
	}
	c.Timeout = 20 * time.Minute
	out := []Advisory{}
	var total int64
	for year := 2002; year <= time.Now().UTC().Year(); year++ {
		log.Printf("source %s: NVD annual file %d", d.ID, year)
		target := fmt.Sprintf("%snvdcve-2.0-%d.json.gz", d.URL, year)
		if e = netpolicy.URL(target, d.AllowedHosts); e != nil {
			return Batch{}, e
		}
		req, e := http.NewRequestWithContext(ctx, "GET", target, nil)
		if e != nil {
			return Batch{}, e
		}
		req.Header.Set("User-Agent", "shixpeer-ward-beacon (+https://shixpeer.com)")
		resp, e := c.Do(req)
		if e != nil {
			return Batch{}, errors.New("NVD annual request failed")
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return Batch{}, fmt.Errorf("NVD year %d returned non-200", year)
		}
		bounded := &checkedReader{ctx: ctx, r: resp.Body, left: d.MaxBytes}
		input, e := gzipReader(ctx, bounded)
		if e != nil {
			resp.Body.Close()
			return Batch{}, e
		}
		part, e := parseNVD(ctx, input)
		if e == nil {
			_, e = io.Copy(io.Discard, input)
		}
		resp.Body.Close()
		if e != nil {
			return Batch{}, fmt.Errorf("NVD year %d: %w", year, e)
		}
		total += d.MaxBytes - bounded.left
		if total > 2<<30 {
			return Batch{}, errors.New("NVD total compressed limit exceeded")
		}
		out = append(out, part...)
		if len(out) > maxRecords {
			return Batch{}, errors.New("NVD total record count exceeded")
		}
	}
	return Batch{Full: true, FetchedAt: time.Now().UTC(), Advisories: out}, nil
}
