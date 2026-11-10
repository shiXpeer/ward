package source

import (
	"archive/tar"
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ulikunitz/xz"
	"io"
	"math"
	"path"
	"shixpeer.com/ward/pkg/vuln"
	"sort"
	"strconv"
	"strings"
	"time"
)

func streamOSVTar(ctx context.Context, r io.Reader, kinds []string, emit func(Advisory) error) error {
	// Cap decoder dictionary independently of compressed and expanded byte limits.
	xr, e := (xz.ReaderConfig{DictCap: 64 << 20}).NewReader(r)
	if e != nil {
		return e
	}
	bounded := &checkedReader{ctx: ctx, r: xr, left: maxStream}
	tr := tar.NewReader(bounded)
	count := 0

	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
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
		limit := int64(maxEntry)
		if strings.HasPrefix(h.Name, "osv/usn/") {
			// Canonical notices can repeat large per-release binary package lists.
			limit = 16 << 20
		}
		if h.Size < 1 || h.Size > limit {
			return fmt.Errorf("OSV tar entry limit exceeded: %s (%d bytes, limit %d)", h.Name, h.Size, limit)
		}
		b, e := io.ReadAll(io.LimitReader(tr, limit+1))
		if e != nil {
			return e
		}
		a, e := parseOSV(compact(b))
		if e != nil {
			return fmt.Errorf("OSV tar record: %w", e)
		}
		if e := emit(a); e != nil {
			return e
		}
		count++
		if count > maxRecords {
			return errors.New("OSV tar record limit exceeded")
		}
	}
	// Consume the xz footer too: corruption after tar EOF is still a failed sync.
	if _, e = io.Copy(io.Discard, bounded); e != nil {
		return e
	}
	if count == 0 {
		return errors.New("source contains no advisories")
	}
	return nil
}

func streamDebian(ctx context.Context, r io.Reader, emit func(Advisory) error) error {
	d := newStreamDecoder(r)
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return errors.New("Debian tracker must be an object")
	}
	count := 0
	for d.More() {
		if e := ctx.Err(); e != nil {
			return e
		}
		name, e := d.Token()
		if e != nil {
			return e
		}
		pkg := name.(string)
		var issues map[string]json.RawMessage
		if e = d.Decode(&issues); e != nil {
			return e
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
				return e
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
					return e
				}
				// fixed_version=0 means not affected. Never manufacture an affected range for it.
				p := Affected{Ecosystem: "Debian:" + release, Name: pkg, EcosystemSpecific: compact(data)}
				if v.Fixed != "" && v.Fixed != "0" {
					p.Ranges = []vuln.Range{{Type: "ECOSYSTEM", Events: []vuln.RangeEvent{{Introduced: "0"}, {Fixed: v.Fixed}}}}
				}
				a.Affected = append(a.Affected, p)
			}
			if e := emit(a); e != nil {
				return e
			}
			count++
			if count > maxRecords {
				return errors.New("Debian record limit exceeded")
			}
		}
	}
	if _, e = d.Token(); e != nil {
		return e
	}
	if e = finishJSON(d); e != nil {
		return e
	}
	if count == 0 {
		return errors.New("source contains no advisories")
	}
	return nil
}
func streamSOFA(r io.Reader, emit func(Advisory) error) error {
	var doc struct {
		OSVersions []struct {
			OSVersion        string
			SecurityReleases []json.RawMessage
		}
	}
	d := newStreamDecoder(r)
	if e := d.Decode(&doc); e != nil {
		return e
	}
	if e := finishJSON(d); e != nil {
		return e
	}
	count := 0

	for _, os := range doc.OSVersions {
		for _, raw := range os.SecurityReleases {
			var s struct {
				ProductVersion, ProductName, ReleaseDate, SecurityInfo, Build string
				CVEs                                                          map[string]bool
			}
			if e := json.Unmarshal(raw, &s); e != nil {
				return e
			}
			if s.ProductVersion == "" || parseTime(s.ReleaseDate).IsZero() {
				return errors.New("SOFA release requires version and date")
			}
			ids := make([]string, 0, len(s.CVEs))
			for id := range s.CVEs {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			for _, id := range ids {
				if !cveID.MatchString(id) {
					return errors.New("invalid SOFA CVE")
				}
				key := "SOFA-" + id + ":" + os.OSVersion + ":" + s.ProductVersion + ":" + s.Build
				// A fix in one branch is not proof every older macOS branch is affected.
				meta, _ := json.Marshal(map[string]any{"os_branch": os.OSVersion, "fixed_version": s.ProductVersion, "build": s.Build, "applicability": "vendor-bulletin-review-required"})
				a := Advisory{ID: key, Aliases: []string{id}, Summary: fmt.Sprintf("%s: security release %s", os.OSVersion, s.ProductVersion), Modified: parseTime(s.ReleaseDate), Raw: compact(raw), Affected: []Affected{{Ecosystem: "macOS", Name: "macOS", EcosystemSpecific: meta}}}
				if safeReference(s.SecurityInfo) {
					a.References = []string{s.SecurityInfo}
				}
				if e := emit(a); e != nil {
					return e
				}
				count++
			}
		}
	}
	if count == 0 {
		return errors.New("source contains no advisories")
	}
	return nil
}

func streamEPSS(r io.Reader, emit func(Advisory) error) error {
	br := bufio.NewReader(r)
	first, e := br.ReadString('\n')
	if e != nil {
		return e
	}
	if !strings.HasPrefix(first, "#") {
		return errors.New("EPSS model/date metadata required")
	}
	var date time.Time
	for _, field := range strings.Split(strings.TrimSpace(strings.TrimPrefix(first, "#")), ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(field), ":")
		if ok && k == "score_date" {
			date = parseTime(v)
		}
	}
	if date.IsZero() {
		return errors.New("EPSS score_date required")
	}
	cr := csv.NewReader(br)
	cr.Comment = '#'
	head, e := cr.Read()
	if e != nil {
		return e
	}
	if strings.Join(head, ",") != "cve,epss,percentile" {
		return errors.New("unexpected EPSS CSV columns")
	}
	count := 0

	for {
		row, e := cr.Read()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if len(row) != 3 || !cveID.MatchString(row[0]) {
			return errors.New("invalid or duplicate EPSS CVE")
		}
		p, e := strconv.ParseFloat(row[1], 64)
		if e != nil || math.IsNaN(p) || p < 0 || p > 1 {
			return errors.New("invalid EPSS score")
		}
		q, e := strconv.ParseFloat(row[2], 64)
		if e != nil || math.IsNaN(q) || q < 0 || q > 1 {
			return errors.New("invalid EPSS percentile")
		}
		raw, _ := json.Marshal(map[string]any{"cve": row[0], "epss": p, "percentile": q, "score_date": date.Format("2006-01-02"), "metadata": strings.TrimSpace(first)})
		if e := emit(Advisory{ID: row[0], Modified: date, Raw: raw, Summary: "EPSS exploitation probability"}); e != nil {
			return e
		}
		count++
		if count > maxRecords {
			return errors.New("EPSS record limit exceeded")
		}
	}
	if count == 0 {
		return errors.New("source contains no advisories")
	}
	return nil
}

func streamNVD(ctx context.Context, r io.Reader, emit func(Advisory) error) error {
	d := newStreamDecoder(r)
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return errors.New("invalid NVD object")
	}
	count := 0
	found := false

	for d.More() {
		key, e := d.Token()
		if e != nil {
			return e
		}
		if key != "vulnerabilities" {
			var skip json.RawMessage
			if e = d.Decode(&skip); e != nil {
				return e
			}
			continue
		}
		if found {
			return errors.New("duplicate NVD array")
		}
		found = true
		t, e = d.Token()
		if e != nil || t != json.Delim('[') {
			return errors.New("invalid NVD array")
		}
		for d.More() {
			if e = ctx.Err(); e != nil {
				return e
			}
			var row struct {
				CVE json.RawMessage `json:"cve"`
			}
			if e = d.Decode(&row); e != nil {
				return e
			}
			a, e := parseNVDRecord(row.CVE)
			if e != nil {
				return e
			}
			if e := emit(a); e != nil {
				return e
			}
			count++
			if count > maxRecords {
				return errors.New("NVD record limit exceeded")
			}
		}
		if _, e = d.Token(); e != nil {
			return e
		}
	}
	if _, e = d.Token(); e != nil {
		return e
	}
	if e = finishJSON(d); e != nil {
		return e
	}
	if !found {
		return errors.New("missing NVD vulnerabilities")
	}
	if count == 0 {
		return errors.New("source contains no advisories")
	}
	return nil
}
func streamRepository(ctx context.Context, r io.Reader, kind string, emit func(Advisory) error) error {
	input, e := gzipReader(ctx, r)
	if e != nil {
		return e
	}
	tr := tar.NewReader(input)
	count := 0

	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		prefix := "/cves/"
		if kind == "ghsa-tar-gzip" {
			prefix = "/advisories/"
		}
		if h.Typeflag != tar.TypeReg || !strings.Contains(h.Name, prefix) || !strings.HasSuffix(h.Name, ".json") {
			continue
		}
		if kind == "cve-tar-gzip" && !cveID.MatchString(strings.TrimSuffix(path.Base(h.Name), ".json")) {
			continue
		}
		if h.Size < 1 || h.Size > maxEntry {
			return errors.New("repository entry limit exceeded")
		}
		b, e := io.ReadAll(io.LimitReader(tr, maxEntry+1))
		if e != nil {
			return e
		}
		var a Advisory
		if kind == "ghsa-tar-gzip" {
			a, e = parseOSV(compact(b))
		} else {
			a, e = parseCVERecord(compact(b))
		}
		if e != nil {
			return e
		}
		if e := emit(a); e != nil {
			return e
		}
		count++
		if count > maxRecords {
			return errors.New("repository record limit exceeded")
		}
	}
	if _, e = io.Copy(io.Discard, input); e != nil {
		return e
	}
	if count == 0 {
		return errors.New("source contains no advisories")
	}
	return nil
}
