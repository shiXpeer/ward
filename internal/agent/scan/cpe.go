package scan

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/internal/cpe"
)

// Only explicitly numeric vendor versions are ordered. Prereleases, OpenSSL
// letter suffixes, epochs and vendor build schemes require review, not guessing.
func decimalVersion(a, b string) (int, error) {
	parse := func(v string) ([]uint64, error) {
		f := strings.Split(v, ".")
		if len(f) < 1 || len(f) > 8 {
			return nil, fmt.Errorf("unsupported numeric version")
		}
		out := make([]uint64, 8)
		for i, s := range f {
			if s == "" || strings.Trim(s, "0123456789") != "" {
				return nil, fmt.Errorf("non-numeric vendor version")
			}
			n, e := strconv.ParseUint(s, 10, 32)
			if e != nil {
				return nil, e
			}
			out[i] = n
		}
		return out, nil
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
func evaluateCPE(row compactdb.Row, version, platform, arch string) decision {
	review := func(reason string) decision { return decision{state: "review", reason: reason} }
	var context struct {
		CPE cpe.Rule `json:"cpe"`
	}
	if json.Unmarshal(row.Context, &context) != nil {
		return review("invalid CPE evidence")
	}
	rule := context.CPE
	m := rule.Match
	name, e := cpe.Parse(m.Criteria)
	if e != nil || name.Key() != row.Package || !m.Vulnerable {
		return review("unsupported or inconsistent CPE identity")
	}
	if rule.Negated {
		return review("NVD applicability includes negation and requires full configuration review")
	}
	unknown := false
	if name.TargetSW != "*" && name.TargetSW != "-" {
		switch name.TargetSW {
		case "mac_os_x", "macos", "mac_os", "macosx", "osx":
			if platform == "" {
				unknown = true
			} else if platform != "darwin" {
				return decision{state: "excluded"}
			}
		case "linux":
			if platform == "" {
				unknown = true
			} else if platform != "linux" {
				return decision{state: "excluded"}
			}
		case "windows", "android", "ios":
			return decision{state: "excluded"}
		default:
			unknown = true
		}
	}
	if name.TargetHW != "*" && name.TargetHW != "-" {
		switch name.TargetHW {
		case "x64", "x86_64", "amd64":
			if arch == "" {
				unknown = true
			} else if arch != "x86_64" && arch != "amd64" {
				return decision{state: "excluded"}
			}
		case "aarch64", "arm64":
			if arch == "" {
				unknown = true
			} else if arch != "arm64" && arch != "aarch64" {
				return decision{state: "excluded"}
			}
		default:
			unknown = true
		}
	}
	for _, s := range []string{name.Update, name.Edition, name.Language, name.SWEdition, name.Other} {
		if s != "*" && s != "-" {
			unknown = true
		}
	}
	if m.StartIncluding != "" && m.StartExcluding != "" || m.EndIncluding != "" && m.EndExcluding != "" {
		return review("conflicting NVD interval boundaries")
	}
	lower := m.StartIncluding
	if lower == "" {
		lower = m.StartExcluding
	}
	upper := m.EndIncluding
	if upper == "" {
		upper = m.EndExcluding
	}
	if lower != "" && upper != "" {
		n, e := decimalVersion(lower, upper)
		if e != nil || n > 0 {
			return review("unsupported or malformed NVD version interval")
		}
	}
	if name.Version != "*" {
		if strings.ContainsAny(name.Version, "*?\\") || name.Version == "-" || name.Version == "" {
			return review("unsupported CPE version binding")
		}
		if name.Version != version {
			// Literal upstream versions must match exactly. Numeric equivalent forms
			// have ambiguous vendor semantics and remain review candidates.
			n, e := decimalVersion(version, name.Version)
			if e == nil && n == 0 {
				unknown = true
			} else {
				return decision{state: "excluded"}
			}
		}
	}
	for _, test := range []struct {
		bound            string
		lower, inclusive bool
	}{{m.StartIncluding, true, true}, {m.StartExcluding, true, false}, {m.EndIncluding, false, true}, {m.EndExcluding, false, false}} {
		if test.bound == "" {
			continue
		}
		n, e := decimalVersion(version, test.bound)
		if e != nil {
			return review("vendor version scheme is not supported for numeric NVD intervals")
		}
		if test.lower && (n < 0 || n == 0 && !test.inclusive) || !test.lower && (n > 0 || n == 0 && !test.inclusive) {
			return decision{state: "excluded"}
		}
	}
	if rule.Complex || row.Review {
		return review("NVD applicability includes AND or another unresolved configuration condition")
	}
	if name.Version == "*" && lower == "" && upper == "" {
		return review("NVD criterion has no version-specific applicability bounds")
	}
	if unknown {
		return review("NVD update, edition, architecture or platform constraint cannot be resolved locally")
	}
	return decision{state: "affected", reason: "explicit upstream identity and installed version match a simple NVD CPE applicability rule"}
}
