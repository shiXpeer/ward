package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"shixpeer.com/ward/internal/agent/database"
	"strconv"
	"strings"

	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/internal/debversion"
	"shixpeer.com/ward/pkg/vuln"
)

func numeric(a, b string) (int, error) {
	parse := func(s string) ([]uint64, error) {
		f := strings.Split(s, ".")
		if len(f) < 2 || len(f) > 4 {
			return nil, errors.New("unsupported numeric version")
		}
		v := make([]uint64, 4)
		for i, x := range f {
			n, e := strconv.ParseUint(x, 10, 32)
			if e != nil {
				return nil, e
			}
			v[i] = n
		}
		return v, nil
	}
	x, e := parse(a)
	if e != nil {
		return 0, e
	}
	y, e := parse(b)
	if e != nil {
		return 0, e
	}
	for i := range x {
		if x[i] < y[i] {
			return -1, nil
		}
		if x[i] > y[i] {
			return 1, nil
		}
	}
	return 0, nil
}

type decision struct {
	state, reason      string
	fixed              []string
	macOSBranchMatched bool
}

const ubuntuNoBoundary = "Ubuntu OSV has no applicable fixed boundary; tracker status and available remediation need review"

func evaluate(row compactdb.Row, version string, exact bool) decision {
	if row.Withdrawn || row.Status == "not_affected" {
		return decision{state: "excluded"}
	}
	var meta struct {
		Fixed         string          `json:"fixed_version"`
		Applicability string          `json:"applicability"`
		Module        json.RawMessage `json:"module_name_regex"`
		Availability  string          `json:"availability"`
	}
	if len(row.Context) > 0 && json.Unmarshal(row.Context, &meta) != nil {
		return decision{state: "review", reason: "invalid vendor context"}
	}
	deb := strings.HasPrefix(row.Ecosystem, "Debian:") || strings.HasPrefix(row.Ecosystem, "Ubuntu:")
	if row.Ecosystem == "macOS" {
		if meta.Fixed != "" {
			// SOFA is release evidence, not a claim about all older OS branches.
			if strings.Split(version, ".")[0] != strings.Split(meta.Fixed, ".")[0] {
				return decision{state: "excluded"}
			}
			n, e := numeric(version, meta.Fixed)
			if e != nil {
				return decision{state: "review", reason: "unsupported macOS version format"}
			}
			if n >= 0 {
				return decision{state: "excluded", macOSBranchMatched: true}
			}
			return decision{state: "review", macOSBranchMatched: true, reason: "vendor lists a newer security release in this macOS branch; applicability requires bulletin review", fixed: []string{meta.Fixed}}
		}
		return decision{state: "review", reason: "macOS advisory has no supported applicability rule"}
	}
	if row.Ecosystem == "npm" || row.Ecosystem == "PyPI" {
		return evaluateLanguage(row, version, exact)
	}
	if !deb {
		return decision{state: "review", reason: "no supported ecosystem version comparator"}
	}
	affected := exact
	unknown := row.Review || meta.Applicability != "" || len(meta.Module) > 0 || (meta.Availability != "" && meta.Availability != "No subscription required")
	fixed := []string{}
	for _, rg := range row.Ranges {
		yes, fix, e := inRange(version, rg, debversion.Compare)
		if e != nil {
			unknown = true
			continue
		}
		if yes {
			affected = true
			fixed = append(fixed, fix...)
		}
	}
	if len(row.Ranges) == 0 && len(row.Versions) == 0 && row.VersionSet == "" {
		unknown = true
	}
	// Canonical encodes both untriaged and known vulnerable records without
	// a fixed boundary; an exact version list does not resolve that ambiguity.
	if strings.HasPrefix(row.Ecosystem, "Ubuntu:") && strings.HasPrefix(row.ID, "UBUNTU-CVE-") && len(fixed) == 0 && (affected || unknown) {
		return decision{state: "review", reason: ubuntuNoBoundary}
	}
	if unknown && row.Source == "debian-tracker" && strings.HasPrefix(row.Ecosystem, "Debian:") {
		switch row.Status {
		case "undetermined":
			return decision{state: "review", reason: "Debian has not determined whether this release is affected"}
		case "open":
			return decision{state: "review", reason: "Debian tracks this as open for the release; the installed version could not be verified", fixed: fixed}
		case "resolved":
			return decision{state: "review", reason: "Debian marks this resolved; the fixed version could not be verified", fixed: fixed}
		default:
			return decision{state: "review", reason: "Debian provides no usable applicability rule for this release", fixed: fixed}
		}
	}
	if unknown {
		return decision{state: "review", reason: "vendor applicability or version conditions need review", fixed: fixed}
	}
	if affected {
		return decision{state: "affected", reason: "installed source version matches the vendor affected-version rule", fixed: fixed}
	}
	return decision{state: "excluded"}
}

// Validate every interval before accepting a match. A malformed later interval
// must not turn a partial parse into a confirmed finding.
func inRange(version string, r vuln.Range, cmp func(string, string) (int, error)) (bool, []string, error) {
	bad := errors.New("unsupported or malformed version range")
	if r.Type != "ECOSYSTEM" || r.Repo != "" || len(r.DatabaseSpecific) > 2 {
		return false, nil, bad
	}
	events := r.Events
	if len(events) > 0 && (r.Introduced != "" || r.Fixed != "" || r.LastAffected != "") {
		return false, nil, bad
	}
	if len(events) == 0 {
		if r.Introduced == "" {
			return false, nil, bad
		}
		events = []vuln.RangeEvent{{Introduced: r.Introduced}}
		if r.Fixed != "" {
			events = append(events, vuln.RangeEvent{Fixed: r.Fixed})
		}
		if r.LastAffected != "" {
			events = append(events, vuln.RangeEvent{LastAffected: r.LastAffected})
		}
	}
	active := false
	lower := ""
	previous := ""
	previousInclusive := false
	matched := false
	fixes := []string{}
	for _, ev := range events {
		count := 0
		value := ""
		for _, s := range []string{ev.Introduced, ev.Fixed, ev.LastAffected, ev.Limit} {
			if s != "" {
				count++
				value = s
			}
		}
		if count != 1 {
			return false, nil, bad
		}
		if value != "0" {
			if _, e := cmp(value, value); e != nil {
				return false, nil, e
			}
		}
		if ev.Introduced != "" {
			if active {
				return false, nil, bad
			}
			if previous != "" {
				n, e := cmp(value, previous)
				if e != nil || n < 0 || (n == 0 && previousInclusive) {
					return false, nil, bad
				}
			}
			active = true
			lower = value
			continue
		}
		if !active {
			return false, nil, bad
		}
		if lower != "0" {
			n, e := cmp(lower, value)
			if e != nil || n > 0 {
				return false, nil, bad
			}
		}
		lo := 1
		var e error
		if lower != "0" {
			lo, e = cmp(version, lower)
			if e != nil {
				return false, nil, e
			}
		}
		hi, e := cmp(version, value)
		if e != nil {
			return false, nil, e
		}
		if lo >= 0 && (hi < 0 || (ev.LastAffected != "" && hi == 0)) {
			matched = true
			if ev.Fixed != "" {
				fixes = append(fixes, ev.Fixed)
			}
		}
		active = false
		previous = value
		previousInclusive = ev.LastAffected != ""
	}
	if active {
		lo := 1
		var e error
		if lower != "0" {
			lo, e = cmp(version, lower)
		}
		if e != nil {
			return false, nil, e
		}
		if lo >= 0 {
			matched = true
		}
	}
	return matched, fixes, nil
}

func evaluateLanguage(row compactdb.Row, version string, exact bool) decision {
	affected := exact
	unknown := row.Review || len(row.Context) > 2
	fixes := []string{}
	compare := func(a, b string) (int, error) {
		if row.Ecosystem == "npm" && (len(strings.Split(a, ".")) != 3 || len(strings.Split(b, ".")) != 3) {
			return 0, errors.New("non-stable semver unsupported")
		}
		return decimalVersion(a, b)
	}
	for _, r := range row.Ranges {
		if row.Ecosystem == "npm" && r.Type == "SEMVER" {
			r.Type = "ECOSYSTEM"
		}
		yes, fixed, e := inRange(version, r, compare)
		if e != nil {
			unknown = true
			continue
		}
		if yes {
			affected = true
			fixes = append(fixes, fixed...)
		}
	}
	if len(row.Ranges) == 0 && len(row.Versions) == 0 && row.VersionSet == "" {
		unknown = true
	}
	if unknown {
		return decision{state: "review", reason: "language-package prerelease/version semantics or vendor conditions need review", fixed: fixes}
	}
	if affected {
		return decision{state: "affected", reason: "installed global package identity and stable numeric version match a supported advisory rule", fixed: fixes}
	}
	return decision{state: "excluded"}
}

func evaluateIndexed(ctx context.Context, db *database.Reader, row compactdb.Row, version string) (decision, error) {
	exact := false
	for _, v := range row.Versions {
		if v == version {
			exact = true
		}
	}
	if row.VersionSet != "" {
		found := false
		err := db.Lookup(ctx, "s", row.VersionSet, 2, func(data []byte) error {
			if compactdb.Digest(data) != row.VersionSet {
				return fmt.Errorf("version set digest mismatch")
			}
			yes, e := compactdb.HasVersion(data, version)
			exact = exact || yes
			found = true
			return e
		})
		if err != nil {
			return decision{}, err
		}
		if !found {
			return decision{}, fmt.Errorf("missing exact version set")
		}
	}
	return evaluate(row, version, exact), nil
}
