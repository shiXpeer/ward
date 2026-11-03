package source

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"

	"shixpeer.com/ward/internal/evidence"
)

// parseRepository reads repository archives without extracting paths or running
// hooks. Only the known data subdirectory for the selected schema is accepted.
func parseRepository(ctx context.Context, r io.Reader, kind string) ([]Advisory, error) {
	input, e := gzipReader(ctx, r)
	if e != nil {
		return nil, e
	}
	tr := tar.NewReader(input)
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
			return nil, errors.New("repository entry limit exceeded")
		}
		b, e := io.ReadAll(io.LimitReader(tr, maxEntry+1))
		if e != nil {
			return nil, e
		}
		var a Advisory
		if kind == "ghsa-tar-gzip" {
			a, e = parseOSV(compact(b))
		} else {
			a, e = parseCVERecord(compact(b))
		}
		if e != nil {
			return nil, e
		}
		if seen[a.ID] {
			return nil, errors.New("duplicate repository advisory ID")
		}
		seen[a.ID] = true
		a.Raw, e = evidence.Pack(a.Raw)
		if e != nil {
			return nil, e
		}
		out = append(out, a)
		if len(out) > maxRecords {
			return nil, errors.New("repository record limit exceeded")
		}
	}
	if _, e = io.Copy(io.Discard, input); e != nil {
		return nil, e
	}
	return validRows(out, nil)
}
func parseCVERecord(raw json.RawMessage) (Advisory, error) {
	var c struct {
		Metadata struct {
			ID                                string `json:"cveId"`
			State, DatePublished, DateUpdated string
		} `json:"cveMetadata"`
		Containers struct {
			CNA struct {
				Title        string
				Descriptions []struct{ Lang, Value string }
				References   []struct{ URL string }
			}
		}
	}
	if e := json.Unmarshal(raw, &c); e != nil {
		return Advisory{}, e
	}
	if !cveID.MatchString(c.Metadata.ID) || (c.Metadata.State != "PUBLISHED" && c.Metadata.State != "REJECTED") {
		return Advisory{}, errors.New("invalid CVE JSON 5 record")
	}
	a := Advisory{ID: c.Metadata.ID, Summary: c.Containers.CNA.Title, Published: parseTime(c.Metadata.DatePublished), Modified: parseTime(c.Metadata.DateUpdated), Withdrawn: c.Metadata.State == "REJECTED", Raw: raw}
	if a.Summary == "" {
		for _, d := range c.Containers.CNA.Descriptions {
			if strings.HasPrefix(d.Lang, "en") {
				a.Summary = d.Value
				break
			}
		}
	}
	for _, ref := range c.Containers.CNA.References {
		if safeReference(ref.URL) {
			a.References = append(a.References, ref.URL)
		}
	}
	// CNA/ADP affected statuses and version schemes remain losslessly in evidence.
	return a, nil
}
