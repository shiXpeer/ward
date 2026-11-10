// Package projection retains matching facts and flags unsupported conditions.
// It is publisher-only; agents do not link upstream parsers or source clients.
package projection

import (
	"encoding/json"
	"fmt"
	"shixpeer.com/ward/internal/beacon/source"
	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/internal/cpe"
	"shixpeer.com/ward/internal/debversion"
	"shixpeer.com/ward/internal/evidence"
	"shixpeer.com/ward/pkg/vuln"
	"strings"
	"time"
)

// Version invalidates compiled input caches when projection semantics change.
const Version = 109

func refs(in []string) []string {
	if len(in) > 3 {
		return in[:3]
	}
	return in
}
func covered(v string, ranges []vuln.Range) bool {
	for _, r := range ranges {
		if r.Type != "ECOSYSTEM" || r.Repo != "" || len(r.DatabaseSpecific) > 2 {
			continue
		}
		valid := len(r.Events) > 0
		for _, ev := range r.Events {
			n := 0
			for _, s := range []string{ev.Introduced, ev.Fixed, ev.LastAffected, ev.Limit} {
				if s != "" {
					n++
				}
			}
			if n != 1 {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		lower := ""
		active := false
		for _, ev := range r.Events {
			if ev.Introduced != "" {
				lower = ev.Introduced
				active = true
				continue
			}
			upper := ev.Fixed
			inclusive := false
			if ev.LastAffected != "" {
				upper = ev.LastAffected
				inclusive = true
			}
			if ev.Limit != "" {
				upper = ev.Limit
			}
			if upper == "" {
				continue
			}
			if active {
				lo, e := debversion.Compare(v, lower)
				if lower == "0" {
					lo = 1
					e = nil
				}
				hi, e2 := debversion.Compare(v, upper)
				if e == nil && e2 == nil && lo >= 0 && (hi < 0 || inclusive && hi == 0) {
					return true
				}
			}
			active = false
		}
		if active {
			lo, e := debversion.Compare(v, lower)
			if lower == "0" {
				lo = 1
				e = nil
			}
			if e == nil && lo >= 0 {
				return true
			}
		}
	}
	return false
}
func redundant(eco string, versions []string, ranges []vuln.Range) bool {
	if !strings.HasPrefix(eco, "Ubuntu:") && !strings.HasPrefix(eco, "Debian:") {
		return false
	}
	if len(ranges) == 0 {
		return false
	}
	for _, v := range versions {
		if !covered(v, ranges) {
			return false
		}
	}
	return true
}

// Project drops prose/raw documents, not version facts. Unrepresented vendor
// conditions are marked for review. Large exact lists live in shared disk sets.
func Project(profile compactdb.Profile, sourceID string, a source.Advisory, put compactdb.Put) error {
	if len(a.Affected) > 0 && (a.Affected[0].Ecosystem == compactdb.UbuntuVEX || strings.HasPrefix(a.Affected[0].Ecosystem, compactdb.UbuntuJammyOVAL) || a.Affected[0].Ecosystem == compactdb.UbuntuJammyPackageOVAL) {
		for _, p := range a.Affected {
			if !profile.Accept(p.Ecosystem) {
				continue
			}
			row := compactdb.Row{Source: sourceID, ID: a.ID, Ecosystem: p.Ecosystem, Package: p.Name, Context: p.EcosystemSpecific}
			data, err := json.Marshal(row)
			if err != nil {
				return err
			}
			if err := put("p", compactdb.PackageKey(p.Ecosystem, p.Name), data); err != nil {
				return err
			}
		}
		return nil
	}
	if sourceID == "canonical-osv" && strings.HasPrefix(a.ID, "USN-") {
		if a.Withdrawn {
			return nil
		}
		for _, p := range a.Affected {
			if !strings.HasPrefix(p.Ecosystem, "Ubuntu:") || !profile.Accept(p.Ecosystem) {
				continue
			}
			ids := usnPackageCVEs(a, p)
			if len(ids) == 0 {
				continue
			}
			row := compactdb.Row{Source: sourceID, ID: a.ID, Aliases: ids, Ecosystem: p.Ecosystem, Package: p.Name, Ranges: p.Ranges}
			raw, err := json.Marshal(row)
			if err != nil {
				return err
			}
			if err := put("p", compactdb.PackageKey(compactdb.UbuntuUSN, compactdb.PackageKey(p.Ecosystem, p.Name)), raw); err != nil {
				return err
			}
		}
		return nil
	}
	base := compactdb.Row{Source: sourceID, ID: a.ID, Aliases: a.Aliases, Severity: a.Severity, Withdrawn: a.Withdrawn, References: refs(a.References), Unmapped: a.UnmappedAffected, Review: a.UnmappedAffected > 0 || len(a.Affected) == 0}
	if !a.KnownExploited && a.Summary != "EPSS exploitation probability" {
		summary := []rune(strings.Join(strings.Fields(a.Summary), " "))
		if len(summary) > 600 {
			summary = append(summary[:599], '…')
		}
		base.Summary = string(summary)
	}
	if !a.Modified.IsZero() {
		base.Modified = a.Modified.UTC().Format(time.RFC3339)
	}
	group := "v"
	if a.KnownExploited {
		group = "r"
		base.KnownExploited = true
		base.Review = false
	}
	var score struct {
		Probability *float64 `json:"epss"`
		Percentile  *float64 `json:"percentile"`
		Date        string   `json:"score_date"`
	}
	raw := a.Raw
	if a.Summary == "EPSS exploitation probability" && len(raw) > 0 {
		if decoded, e := evidence.Unpack(raw); e == nil {
			raw = decoded
		}
		if json.Unmarshal(raw, &score) == nil && score.Probability != nil {
			group = "r"
			base.Review = false
			base.Probability = score.Probability
			base.Percentile = score.Percentile
			base.Modified = score.Date
		}
	}
	ids := append([]string{a.ID}, a.Aliases...)
	unique := map[string]bool{}
	for _, id := range ids {
		if unique[id] {
			continue
		}
		unique[id] = true
		b, e := json.Marshal(base)
		if e != nil {
			return e
		}
		if len(b) > compactdb.MaxRow {
			return fmt.Errorf("compact metadata exceeds row limit")
		}
		if e = put(group, id, b); e != nil {
			return e
		}
	}
	for _, p := range a.Affected {
		if !profile.Accept(p.Ecosystem) {
			continue
		}
		if p.Ecosystem == "CPE" {
			var rule cpe.Rule
			if err := json.Unmarshal(p.DatabaseSpecific, &rule); err != nil {
				return err
			}
			ctx, _ := json.Marshal(map[string]any{"cpe": rule})
			r := compactdb.Row{Source: sourceID, ID: a.ID, Withdrawn: a.Withdrawn, Ecosystem: "CPE", Package: p.Name, Context: ctx, Review: rule.Complex}
			b, err := json.Marshal(r)
			if err != nil {
				return err
			}
			if len(b) > compactdb.MaxRow {
				return fmt.Errorf("CPE rule exceeds row limit")
			}
			if err = put("p", compactdb.PackageKey("CPE", p.Name), b); err != nil {
				return err
			}
			continue
		}
		r := compactdb.Row{Source: sourceID, ID: a.ID, Withdrawn: a.Withdrawn}
		r.Ecosystem = p.Ecosystem
		r.Package = p.Name
		r.Unmapped = 0
		r.Ranges = p.Ranges
		for _, rg := range r.Ranges {
			if len(rg.DatabaseSpecific) > 2 {
				r.Review = true
			}
			for _, ev := range rg.Events {
				count := 0
				for _, v := range []string{ev.Introduced, ev.Fixed, ev.LastAffected, ev.Limit} {
					if v != "" {
						count++
					}
				}
				if count != 1 {
					r.Review = true
				}
			}
		}
		r.Versions = p.Versions
		r.SourcePackage = strings.HasPrefix(p.Ecosystem, "Ubuntu:") || strings.HasPrefix(p.Ecosystem, "Debian:")
		if redundant(p.Ecosystem, r.Versions, r.Ranges) {
			r.Versions = nil
		}
		context := map[string]json.RawMessage{}
		if len(p.EcosystemSpecific) > 0 {
			data, e := evidence.Unpack(p.EcosystemSpecific)
			if e != nil {
				return e
			}
			var obj map[string]json.RawMessage
			if e = json.Unmarshal(data, &obj); e != nil {
				r.Review = true
			} else {
				for k, v := range obj {
					switch k {
					case "binaries":
						r.SourcePackage = true
					case "status", "fixed_version", "urgency", "nodsa", "nodsa_reason", "availability", "ubuntu_priority", "os_branch", "fixed_version_branch", "fixed_version_string", "build", "applicability", "module_name_regex":
						context[k] = v
					default:
						r.Review = true
					}
				}
			}
		}
		// Vendor-specific fields can contain conditions not represented by ranges.
		if len(p.DatabaseSpecific) > 2 {
			r.Review = true
		}
		if len(context) > 0 {
			r.Context, _ = json.Marshal(context)
			json.Unmarshal(context["status"], &r.Status)
			var fixed string
			json.Unmarshal(context["fixed_version"], &fixed)
			if fixed == "0" && r.Status == "resolved" {
				r.Status = "not_affected"
			}
		}
		if len(r.Ranges) == 0 && len(r.Versions) == 0 && r.Status != "not_affected" {
			r.Review = true
		}
		if len(r.Versions) > 0 {
			encoded, _ := json.Marshal(r.Versions)
			if len(encoded) > 2048 {
				set, e := compactdb.EncodeVersions(r.Versions)
				if e != nil {
					return e
				}
				digest := compactdb.Digest(set)
				if e = put("s", digest, set); e != nil {
					return e
				}
				r.VersionSet = digest
				r.Versions = nil
			}
		}
		b, e := json.Marshal(r)
		if e != nil {
			return e
		}
		if len(b) > compactdb.MaxRow {
			return fmt.Errorf("compact rule exceeds row limit")
		}
		if e = put("p", compactdb.PackageKey(r.Ecosystem, r.Package), b); e != nil {
			return e
		}
	}
	return nil
}
