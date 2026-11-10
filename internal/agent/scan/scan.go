// Package scan compares local inventory with a single authenticated disk
// publication. It contains no HTTP client and never updates installed software.
package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"shixpeer.com/ward/internal/agent/database"
	"shixpeer.com/ward/internal/atomicfile"
	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/internal/cpe"
	"shixpeer.com/ward/internal/snapshot"
	"shixpeer.com/ward/pkg/inventory"
)

const FormatVersion = 1
const maxFindings = 10000
const maxComponentFindings = 64

type Finding struct {
	Summary        string        `json:"summary,omitempty"`
	FixedSource    string        `json:"fixed_source,omitempty"`
	Origin         string        `json:"origin,omitempty"`
	MatchVersion   string        `json:"match_version,omitempty"`
	RuleMatches    int           `json:"rule_matches"`
	Evidence       compactdb.Row `json:"evidence"`
	Status         string        `json:"status"`
	Priority       string        `json:"priority"`
	Component      string        `json:"component"`
	Version        string        `json:"installed_version"`
	Ecosystem      string        `json:"ecosystem"`
	Source         string        `json:"source"`
	ID             string        `json:"id"`
	Aliases        []string      `json:"aliases,omitempty"`
	Severity       string        `json:"severity"`
	KnownExploited bool          `json:"known_exploited"`
	EPSS           *float64      `json:"epss,omitempty"`
	Fixed          []string      `json:"fixed_versions,omitempty"`
	Reason         string        `json:"reason"`
	Recommendation string        `json:"recommendation"`
	References     []string      `json:"references,omitempty"`
}
type Component struct {
	homebrewBottle   string
	vexProduct       string
	binaries         []inventory.Package
	vexIdentityIssue string
	Name             string `json:"name"`
	Version          string `json:"version"`
	Ecosystem        string `json:"ecosystem,omitempty"`
	Origin           string `json:"origin"`
	Product          string `json:"product,omitempty"`
	MatchVersion     string `json:"match_version,omitempty"`
	Reason           string `json:"reason,omitempty"`
	Rules            int    `json:"rules"`
	Result           string `json:"result"`
}
type Publication struct {
	Revision int64                    `json:"revision"`
	Created  time.Time                `json:"created_at"`
	Expires  time.Time                `json:"expires_at"`
	Profile  compactdb.Profile        `json:"profile"`
	Sources  []compactdb.SourceStatus `json:"sources"`
}
type Report struct {
	Hostname        string             `json:"hostname,omitempty"`
	UbuntuEvidence  UbuntuEvidence     `json:"ubuntu_evidence"`
	ReviewScopes    map[string]int     `json:"review_scopes,omitempty"`
	ReviewReasons   map[string]int     `json:"review_reasons,omitempty"`
	FormatVersion   int                `json:"format_version"`
	GeneratedAt     time.Time          `json:"generated_at"`
	Offline         bool               `json:"offline"`
	Status          string             `json:"status"`
	Database        *Publication       `json:"database,omitempty"`
	Inventory       inventory.Snapshot `json:"inventory"`
	Components      []Component        `json:"components"`
	Findings        []Finding          `json:"findings"`
	Coverage        []inventory.Note   `json:"coverage"`
	OmittedFindings int                `json:"omitted_findings,omitempty"`
	VEXResolved     int                `json:"ubuntu_vex_resolved,omitempty"`
	Confirmed       int                `json:"confirmed"`
	Review          int                `json:"requires_review"`
}

type UbuntuEvidence struct {
	PackageOVALComponents int  `json:"package_oval_components_checked"`
	PackageOVALMatches    int  `json:"package_oval_affected"`
	USNIndexed            bool `json:"usn_index_declared"`
	USNComponents         int  `json:"usn_components_with_candidate_fixes"`
	USNFindings           int  `json:"usn_linked_findings"`
}

func reviewScope(origin string) string {
	switch {
	case origin == "running-kernel":
		return "Running kernel"
	case strings.HasPrefix(origin, "docker:"):
		return "Containers"
	default:
		return "Host packages and applications"
	}
}

func New(s inventory.Snapshot) Report {
	return Report{FormatVersion: FormatVersion, GeneratedAt: time.Now().UTC(), Offline: true, Status: "partial", Inventory: s, Components: components(s, nil), Findings: []Finding{}, Coverage: append([]inventory.Note{}, s.Coverage...)}
}
func ecosystem(s inventory.Snapshot) string {
	r := s.Host.Release
	switch r["ID"] {
	case "debian":
		if r["VERSION_CODENAME"] != "" {
			return "Debian:" + r["VERSION_CODENAME"]
		}
		if r["VERSION_ID"] != "" {
			return "Debian:" + strings.Split(r["VERSION_ID"], ".")[0]
		}
	case "ubuntu":
		if r["VERSION_ID"] != "" && strings.HasSuffix(r["VERSION_ID"], ".04") {
			var year int
			if _, err := fmt.Sscanf(r["VERSION_ID"], "%d.04", &year); err != nil || year%2 != 0 {
				return ""
			}
			return "Ubuntu:" + r["VERSION_ID"] + ":LTS"
		}
	}
	return ""
}
func components(s inventory.Snapshot, policy *snapshot.ProductPolicy) []Component {
	if policy == nil {
		policy = &snapshot.ProductPolicy{}
	}
	out := []Component{}
	seen := map[string]int{}
	add := func(c Component) {
		key := c.Ecosystem + "\x00" + c.Name + "\x00" + c.Version + "\x00" + c.Origin + "\x00" + c.Product + "\x00" + c.MatchVersion
		if i, ok := seen[key]; ok {
			out[i].binaries = append(out[i].binaries, c.binaries...)
		} else {
			seen[key] = len(out)
			c.Result = "NOT_CHECKED"
			out = append(out, c)
		}
	}
	if v := s.Host.Release["ProductVersion"]; v != "" {
		add(Component{Name: "macOS", Version: v, Ecosystem: "macOS", Origin: "operating-system"})
	}
	eco := ecosystem(s)
	if k := s.RunningKernel; k != nil {
		c := Component{Name: "running-kernel", Version: k.Release, Origin: "running-kernel", Reason: k.Detail}
		if k.Status == "IDENTIFIED" && k.SourceName != "" && k.SourceVersion != "" && eco != "" {
			c.Name = k.SourceName
			c.Version = k.SourceVersion
			c.Ecosystem = eco
			c.vexProduct, c.vexIdentityIssue = vexProduct(eco, s.Host.Release, c.Name, c.Version)
		}
		add(c)
	}
	for _, p := range s.Packages {
		c := Component{Name: p.Name, Version: p.Version, Origin: p.Manager}
		if p.Manager == "dpkg" && eco != "" {
			c.binaries = []inventory.Package{p}

			c.Ecosystem = eco
			if p.SourceName != "" {
				c.Name = p.SourceName
			}
			if p.SourceVersion != "" {
				c.Version = p.SourceVersion
			}
			c.vexProduct, c.vexIdentityIssue = vexProduct(eco, s.Host.Release, c.Name, c.Version)
		}
		if p.Manager == "homebrew-formula" && p.Provenance == "homebrew/core" && p.UpstreamVersion != "" {
			if product := policy.Formula[p.Name]; product != "" {
				c.Ecosystem = "CPE"
				c.Product = product
				c.MatchVersion = p.UpstreamVersion
				c.homebrewBottle = p.HomebrewBottle
			}
		}
		if c.Ecosystem == "" {
			switch {
			case p.Manager == "homebrew-cask":
				c.Reason = "Homebrew cask has no verified advisory mapping; the application bundle is checked separately when supported"
			case p.Manager == "homebrew-formula" && p.Provenance != "homebrew/core":
				c.Reason = "Installed receipt does not establish a stable Homebrew core release"
			case p.Manager == "homebrew-formula" && p.UpstreamVersion == "":
				c.Reason = "Homebrew receipt has no comparable upstream release version"
			case p.Manager == "homebrew-formula":
				c.Reason = "Homebrew core formula has no verified advisory mapping"
			default:
				c.Reason = "Package has no supported advisory ecosystem"
			}
		}
		add(c)
	}
	for _, container := range s.Containers {
		containerEco := ecosystem(inventory.Snapshot{Host: inventory.Host{Release: container.Release}})
		for _, p := range container.Packages {
			c := Component{Name: p.Name, Version: p.Version, Ecosystem: containerEco, Origin: "docker:" + container.Name, binaries: []inventory.Package{p}}
			if p.SourceName != "" {
				c.Name = p.SourceName
			}
			if p.SourceVersion != "" {
				c.Version = p.SourceVersion
			}
			c.vexProduct, c.vexIdentityIssue = vexProduct(containerEco, container.Release, c.Name, c.Version)
			add(c)
		}
	}
	for _, a := range s.Applications {
		c := Component{Name: a.Name, Version: a.Version, Origin: "application-bundle", Reason: "bundle identifier has no explicit upstream mapping"}
		if product := policy.Bundle[a.Identifier]; product != "" && a.VersionKind == "release" {
			c.Ecosystem = "CPE"
			c.Product = product
			c.MatchVersion = a.Version
			c.Reason = ""
		}
		if a.VersionKind != "release" {
			c.Reason = "application release version is unavailable; build numbers are not treated as upstream release versions"
		}
		add(c)
	}
	for _, d := range s.Dependencies {
		if d.Ecosystem == "npm" || d.Ecosystem == "PyPI" {
			add(Component{Name: d.Name, Version: d.Version, Ecosystem: d.Ecosystem, Origin: "global-dependency"})
		}
	}
	return out
}

func Run(ctx context.Context, r *Report, db *database.Reader) error {
	return RunWithProgress(ctx, r, db, nil)
}

// RunWithProgress reports completed components before starting the next one.
func RunWithProgress(ctx context.Context, r *Report, db *database.Reader, progress func(int, int, int, int, string)) error {
	return run(ctx, r, db, progress, nil)
}

func RunForAdvisories(ctx context.Context, r *Report, db *database.Reader, ids map[string]bool) error {
	return run(ctx, r, db, nil, ids)
}

func run(ctx context.Context, r *Report, db *database.Reader, progress func(int, int, int, int, string), ids map[string]bool) error {
	m := db.Manifest
	r.Database = &Publication{Revision: m.Revision, Created: m.CreatedAt, Expires: m.ExpiresAt, Profile: m.Profile, Sources: m.Sources}
	policy := m.ProductPolicy
	legacyDockerCoverage := false
	if policy == nil {
		for _, source := range m.Sources {
			if slices.Contains(source.RuleFormats, cpe.DockerDesktopRuleFormat) {
				legacyDockerCoverage = true
				policy = &snapshot.ProductPolicy{Bundle: map[string]string{"com.docker.docker": cpe.DockerDesktop}}
				break
			}
		}
	}
	r.Components = components(r.Inventory, policy)
	r.Coverage = append(r.Coverage, inventory.Note{Code: inventory.NotChecked, Source: "matching", Detail: "confirmed rules cover Debian/Ubuntu source packages and explicitly mapped simple NVD CPE products; unsupported identities/conditions and kernels without a supported loaded-version signature remain unchecked"})

	if m.ProductPolicy == nil {
		detail := "The signed database does not include a product catalog; update from a Beacon that publishes product policy."
		if legacyDockerCoverage {
			detail += " Docker Desktop is checked using the signed legacy Docker Desktop coverage marker."
		}
		r.Coverage = append(r.Coverage, inventory.Note{Code: inventory.NotChecked, Source: "product-policy", Detail: detail})
	}
	limitedQueries := 0
	hasVEX, hasOVAL, hasPackageOVAL := false, false, false
	for _, source := range m.Sources {
		for _, format := range source.RuleFormats {
			hasVEX = hasVEX || format == compactdb.UbuntuVEX
			r.UbuntuEvidence.USNIndexed = r.UbuntuEvidence.USNIndexed || format == compactdb.UbuntuUSN
			hasOVAL = hasOVAL || format == compactdb.UbuntuJammyOVAL
			hasPackageOVAL = hasPackageOVAL || format == compactdb.UbuntuJammyPackageOVAL
		}
	}
	for i := range r.Components {
		c := &r.Components[i]
		if progress != nil {
			progress(i, len(r.Components), r.Confirmed, r.Review, c.Name)
		}
		if c.Ecosystem == "" || c.Version == "" {
			c.Result = "NOT_CHECKED"
			if c.Version == "" {
				c.Reason = "installed version was not collected"
			}
			continue
		}
		if !m.Profile.Accept(c.Ecosystem) {
			c.Result = "NOT_CHECKED"
			c.Reason = "publication profile excludes this ecosystem"
			continue
		}
		if c.Ecosystem == "CPE" {
			available := false
			for _, source := range m.Sources {
				for _, format := range source.RuleFormats {
					if format == cpe.RuleFormat || (legacyDockerCoverage && c.Product == cpe.DockerDesktop && format == cpe.DockerDesktopRuleFormat) {
						available = true
					}
				}
			}
			if !available {
				c.Result = "NOT_CHECKED"
				c.Reason = "installed publication predates indexed NVD CPE rules for this product mapping; refresh Beacon and update the agent database"
				continue
			}
		}
		c.Result = "NO_ADVISORY_FOUND"
		queryName, version := c.Name, c.Version
		if c.Product != "" {
			queryName = c.Product
		}
		if c.MatchVersion != "" {
			version = c.MatchVersion
		}
		packageKey := compactdb.PackageKey(c.Ecosystem, queryName)
		var vex map[string]string
		vexFailed := false
		if hasVEX && c.vexProduct != "" {
			var err error
			vex, err = matchVEX(ctx, db, c.vexProduct, packageKey, version)
			if err != nil {
				vexFailed = true
				if ctx.Err() != nil {
					return ctx.Err()
				}
				r.Coverage = append(r.Coverage, inventory.Note{Code: inventory.Unresolved, Source: "ubuntu-vex", Detail: fmt.Sprintf("%s %s (%s, %s): %v", c.Name, c.Version, c.Ecosystem, c.Origin, err)})
			}
		}
		var oval map[string]bool
		if hasOVAL && c.Origin == "running-kernel" && c.Ecosystem == "Ubuntu:22.04:LTS" &&
			r.Inventory.Host.Release["VERSION_CODENAME"] == "jammy" && r.Inventory.RunningKernel != nil {
			var err error
			oval, err = matchingJammyKernelOVAL(ctx, db, c.Name, r.Inventory.RunningKernel.Release)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				r.Coverage = append(r.Coverage, inventory.Note{Code: inventory.Unresolved, Source: "ubuntu-oval-jammy", Detail: fmt.Sprintf("%s %s: %v", c.Name, c.Version, err)})
			}
		}
		var packageOVAL map[string]bool
		if hasPackageOVAL && c.Ecosystem == "Ubuntu:22.04:LTS" && len(c.binaries) > 0 {
			var err error
			packageOVAL, err = matchingJammyPackageOVAL(ctx, db, c.binaries)
			if err == nil {
				r.UbuntuEvidence.PackageOVALComponents++
			}
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				r.Coverage = append(r.Coverage, inventory.Note{Code: inventory.Unresolved, Source: "ubuntu-oval-jammy", Detail: fmt.Sprintf("%s %s (%s): %v", c.Name, c.Version, c.Origin, err)})
			}
		}
		var usnFixes map[string]usnFix
		if strings.HasPrefix(c.Ecosystem, "Ubuntu:") {
			var err error
			usnFixes, err = ubuntuUSNFixes(ctx, db, c.Ecosystem, c.Name, c.Version)
			if len(usnFixes) > 0 {
				r.UbuntuEvidence.USNComponents++
			}
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				r.Coverage = append(r.Coverage, inventory.Note{Code: inventory.Unresolved, Source: "ubuntu-usn", Detail: fmt.Sprintf("%s %s: %v", c.Name, c.Version, err)})
			}
		}
		seen := map[string]struct{ state, reason string }{}
		vexResolved := map[string]bool{}
		retained := map[string]Finding{}
		commitFindings := func() {
			for _, f := range retained {
				r.Findings = append(r.Findings, f)
			}
			sort.Slice(r.Findings, func(i, j int) bool { return findingLess(r.Findings[i], r.Findings[j]) })
			if len(r.Findings) > maxFindings {
				keep := maxFindings
				for keep < len(r.Findings) && urgentFinding(r.Findings[keep]) {
					keep++
				}
				clear(r.Findings[keep:])
				r.Findings = r.Findings[:keep]
			}
			r.OmittedFindings = r.Confirmed + r.Review - len(r.Findings)
		}
		macOSBranchMatched := false
		err := db.Lookup(ctx, "p", packageKey, maxPackageRules, func(raw []byte) error {
			var row compactdb.Row
			if e := json.Unmarshal(raw, &row); e != nil {
				return e
			}
			if row.Ecosystem != c.Ecosystem || row.Package != queryName {
				return fmt.Errorf("package index identity mismatch")
			}
			c.Rules++
			if len(ids) > 0 && !ids[row.ID] {
				return nil
			}
			d, err := evaluateIndexed(ctx, db, row, version)
			if err != nil {
				return err
			}
			macOSBranchMatched = macOSBranchMatched || d.macOSBranchMatched
			if row.Ecosystem == "CPE" && !row.Withdrawn {
				platform := r.Inventory.Host.OS
				if platform == "" && strings.HasPrefix(r.Inventory.Host.Uname, "Linux ") {
					platform = "linux"
				}
				if platform == "" && strings.HasPrefix(r.Inventory.Host.Uname, "Darwin ") {
					platform = "darwin"
				}
				if r.Inventory.Host.Release["ProductVersion"] != "" {
					platform = "darwin"
				}
				d = evaluateCPE(row, version, platform, r.Inventory.Host.Architecture)
				if correctedNVDMatch(m.ProductPolicy, row, c.Origin, c.Name, c.Version, version, platform, c.homebrewBottle) {
					d = decision{state: "excluded"}
				}
			}
			matchedPackageOVAL := false
			if d.reason == ubuntuNoBoundary && row.Source == "canonical-osv" {
				id := strings.TrimPrefix(row.ID, "UBUNTU-")
				status := vex[id]
				if resolved := resolveVEX(status); resolved.state != "" {
					d = resolved
					if !vexResolved[row.ID] {
						r.VEXResolved++
						vexResolved[row.ID] = true
					}
				} else if status == "" && !vexFailed && packageOVAL[id] {
					matchedPackageOVAL = true
					d = decision{state: "affected", reason: "Canonical Ubuntu OVAL matches an installed Jammy binary package and its version"}
				} else if status == "" && !vexFailed && oval[id] {
					d = decision{state: "affected", reason: "Canonical Ubuntu OVAL matches this running Jammy kernel; the matching rule provides no fixed version"}
				} else {
					d.reason = ubuntuReviewReason(hasVEX, c.vexIdentityIssue, vexFailed, status)
				}
			}
			fixedSource := ""
			if d.state == "affected" && row.Source == "canonical-osv" {
				if fix := usnFixes[strings.TrimPrefix(row.ID, "UBUNTU-")]; fix.version != "" {
					if len(d.fixed) == 0 {
						d.fixed = []string{fix.version}
					}
					if len(d.fixed) == 1 && d.fixed[0] == fix.version {
						fixedSource = fix.notice
					}
				}
			}
			if d.state == "excluded" {
				return nil
			}
			identity := queryName + "\x00" + version + "\x00" + c.Ecosystem + "\x00" + c.Name + "\x00" + c.Origin + "\x00" + c.Version + "\x00" + row.Source + "\x00" + row.ID
			previous := seen[identity]
			if previous.state != "" && !(previous.state == "review" && d.state == "affected") {
				if f, ok := retained[identity]; ok {
					f.RuleMatches++
					retained[identity] = f
				}
				return nil
			}
			seen[identity] = struct{ state, reason string }{d.state, d.reason}
			if previous.state == "review" {
				r.Review--
				r.ReviewScopes[reviewScope(c.Origin)]--
				if r.ReviewScopes[reviewScope(c.Origin)] == 0 {
					delete(r.ReviewScopes, reviewScope(c.Origin))
				}
				r.ReviewReasons[previous.reason]--
				if r.ReviewReasons[previous.reason] == 0 {
					delete(r.ReviewReasons, previous.reason)
				}
			}
			f := Finding{Evidence: row, Status: d.state, Component: c.Name, Version: c.Version, MatchVersion: version, Origin: c.Origin, RuleMatches: 1, Ecosystem: c.Ecosystem, Source: row.Source, ID: row.ID, Severity: "UNKNOWN", Fixed: d.fixed, FixedSource: fixedSource, Reason: d.reason}
			if prior, ok := retained[identity]; ok {
				f.RuleMatches = prior.RuleMatches + 1
			}
			if f.Status == "affected" {
				r.Confirmed++
				if matchedPackageOVAL {
					r.UbuntuEvidence.PackageOVALMatches++
				}
				if fixedSource != "" {
					r.UbuntuEvidence.USNFindings++
				}
				c.Result = "AFFECTED"
				f.Recommendation = recommendation(c.Ecosystem)
				if c.Origin == "running-kernel" {
					f.Recommendation = "Check the vendor advisory and the available fixed kernel package before scheduling an update or reboot."
				}
			} else {
				r.Review++
				if r.ReviewScopes == nil {
					r.ReviewScopes = map[string]int{}
				}
				r.ReviewScopes[reviewScope(c.Origin)]++
				if r.ReviewReasons == nil {
					r.ReviewReasons = map[string]int{}
				}
				r.ReviewReasons[d.reason]++
				if c.Result != "AFFECTED" {
					c.Result = "REQUIRES_REVIEW"
				}
				f.Recommendation = "Review the vendor advisory before treating this as an applicable vulnerability."
				if c.Ecosystem == "macOS" {
					f.Recommendation = "Check the linked Apple security bulletin and install the supported security update for this macOS branch."
				}
			}
			// Review entries cannot outrank affected findings. Avoid expensive
			// enrichment when a review cannot enter the bounded sample.
			f.Priority = priority(f)
			worstKey := ""
			var worst Finding
			if _, ok := retained[identity]; !ok && len(retained) >= maxComponentFindings {
				for k, v := range retained {
					if worstKey == "" || findingLess(worst, v) {
						worstKey = k
						worst = v
					}
				}
				if f.Status == "review" && !findingLess(f, worst) {
					return nil
				}
			}
			if err := enrich(ctx, db, &f); err != nil {
				return err
			}
			f.Priority = priority(f)
			if worstKey != "" && !urgentFinding(f) {
				if urgentFinding(worst) || !findingLess(f, worst) {
					return nil
				}
				delete(retained, worstKey)
			}
			retained[identity] = f
			return nil
		})
		commitFindings()
		if err != nil {
			c.Result = "INCOMPLETE"
			if errors.Is(err, database.ErrLookupLimit) {
				c.Reason = err.Error()
				limitedQueries++
				continue
			}
			return err
		}
		if c.Result == "NO_ADVISORY_FOUND" {
			if c.Ecosystem == "macOS" && !macOSBranchMatched {
				c.Result = "NOT_CHECKED"
				c.Reason = "The installed publication has no macOS security release rules for this major version"
			} else if c.Rules > 0 {
				c.Result = "NO_MATCH_IN_AVAILABLE_RULES"
			}
		}
	}
	if !m.ExpiresAt.After(time.Now()) {
		return fmt.Errorf("database expired during scan")
	}
	if limitedQueries > 0 {
		return fmt.Errorf("%d component queries hit the lookup work limit; other components were scanned", limitedQueries)
	}
	return nil
}
func findingLess(a, b Finding) bool {
	if a.Priority != b.Priority {
		return a.Priority < b.Priority
	}
	if (len(a.Fixed) > 0) != (len(b.Fixed) > 0) {
		return len(a.Fixed) > 0
	}
	if a.Component != b.Component {
		return a.Component < b.Component
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	if a.Origin != b.Origin {
		return a.Origin < b.Origin
	}
	if a.Source != b.Source {
		return a.Source < b.Source
	}
	return a.ID < b.ID
}
func enrich(ctx context.Context, db *database.Reader, f *Finding) error {
	// Package rules intentionally store source+ID; fetch metadata for that exact
	// source, never infer a global withdrawal from another publisher.
	err := db.Lookup(ctx, "v", f.ID, 10000, func(raw []byte) error {
		var row compactdb.Row
		if e := json.Unmarshal(raw, &row); e != nil {
			return e
		}
		if row.Source == f.Source && row.ID == f.ID {
			f.Summary = row.Summary
			f.Aliases = row.Aliases
			f.References = row.References
			if row.Severity != "" {
				f.Severity = row.Severity
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	ids := append([]string{f.ID}, f.Aliases...)
	for _, id := range ids {
		if err = db.Lookup(ctx, "r", id, 100, func(raw []byte) error {
			var row compactdb.Row
			if e := json.Unmarshal(raw, &row); e != nil {
				return e
			}
			if !row.Withdrawn {
				f.KnownExploited = f.KnownExploited || row.KnownExploited
				if row.Probability != nil {
					f.EPSS = row.Probability
				}
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}
func priority(f Finding) string {
	if f.Status != "affected" {
		return "P4-review"
	}
	if f.KnownExploited {
		return "P0-known-exploited"
	}
	switch strings.ToUpper(f.Severity) {
	case "CRITICAL":
		return "P1-critical"
	case "HIGH":
		return "P2-high"
	}
	return "P3-other"
}
func Save(dir string, r Report) error {
	if err := atomicfile.JSON(filepath.Join(dir, "report.json"), r); err != nil {
		return err
	}
	return atomicfile.Write(filepath.Join(dir, "report.md"), []byte(Markdown(r)), 0600)
}
func cell(s string) string {
	s = strings.NewReplacer("|", "\\|", "\n", " ", "\r", " ", "<", "&lt;", ">", "&gt;", "[", "\\[", "]", "\\]", "!", "\\!", "\\", "\\\\", "`", "\\`").Replace(s)
	return s
}
func Markdown(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Shixpeer Ward local scan\n\nGenerated: %s\n\nStatus: **%s**. Confirmed rule matches: **%d**. Requires review: **%d**.\n\n", r.GeneratedAt.Format(time.RFC3339), r.Status, r.Confirmed, r.Review)
	if r.OmittedFindings > 0 {
		fmt.Fprintf(&b, "Finding details omitted by output limits: %d. Counts include omitted findings.\n\n", r.OmittedFindings)
	}
	b.WriteString("Offline scan. A missing advisory or zero findings does not mean this system is safe. Matching a vendor version rule does not prove runtime exploitability.\n\n")
	if r.Database != nil {
		fmt.Fprintf(&b, "Database revision: %d. Expires: %s. Profile: %s. Sources: %d.\n\n", r.Database.Revision, r.Database.Expires.Format(time.RFC3339), r.Database.Profile, len(r.Database.Sources))
	}
	e := r.UbuntuEvidence
	if e.PackageOVALComponents > 0 || e.USNIndexed || e.USNComponents > 0 {
		fmt.Fprintf(&b, "## Ubuntu evidence\n\n- Package OVAL: %d components checked, %d findings resolved.\n- USN: %d components with candidate fixes, %d findings linked to a notice.\n\n", e.PackageOVALComponents, e.PackageOVALMatches, e.USNComponents, e.USNFindings)
	}

	if len(r.ReviewScopes) > 0 {
		b.WriteString("## Review by installation scope\n\n")
		for _, scope := range sortedReviewReasons(r.ReviewScopes) {
			fmt.Fprintf(&b, "- **%d** — %s\n", r.ReviewScopes[scope], cell(scope))
		}
		b.WriteString("\n")
	}

	if len(r.ReviewReasons) > 0 {
		b.WriteString("## Why records need review\n\n")
		for _, reason := range sortedReviewReasons(r.ReviewReasons) {
			fmt.Fprintf(&b, "- **%d** — %s\n", r.ReviewReasons[reason], cell(reason))
		}
		b.WriteString("\n")
	}

	if r.VEXResolved > 0 {
		fmt.Fprintf(&b, "\nCanonical VEX resolved %d ambiguous Ubuntu applicability records.\n", r.VEXResolved)
	}

	if k := r.Inventory.RunningKernel; k != nil {
		fmt.Fprintf(&b, "## Running kernel\n\nRelease: %s. Status: %s. Loaded source: %s %s. Installed image source: %s. Reboot pending: %t. %s\n\n", cell(k.Release), cell(k.Status), cell(k.SourceName), cell(k.SourceVersion), cell(k.InstalledSourceVersion), k.RebootRequired, cell(k.Detail))
		if len(k.RebootPackages) > 0 {
			fmt.Fprintf(&b, "Ubuntu reboot marker packages: %s.\n\n", cell(strings.Join(k.RebootPackages, ", ")))
		}
	}
	b.WriteString("## Findings and recommended actions\n\n")
	b.WriteString("Related advisories share one explanation and action. Individual evidence and references are in report.json.\n\n")
	binaryNames := map[string][]string{}
	for _, p := range r.Inventory.Packages {
		if p.Manager != "dpkg" {
			continue
		}
		name, version := p.SourceName, p.SourceVersion
		if name == "" {
			name = p.Name
		}
		if version == "" {
			version = p.Version
		}
		k := name + "\x00" + version
		if !slices.Contains(binaryNames[k], p.Name) {
			binaryNames[k] = append(binaryNames[k], p.Name)
		}
	}
	groups := groupGuidance(r.Findings, true)
	sort.SliceStable(groups, func(i, j int) bool {
		a, b := groups[i].example, groups[j].example
		if a.Status != b.Status {
			return a.Status == "affected"
		}
		return consoleFindingLess(a, b)
	})
	for _, g := range groups {
		f := g.example
		fmt.Fprintf(&b, "- **%s %s** (%s, %s) · %s · %s · %s\n", cell(f.Component), cell(f.Version), cell(f.Origin), cell(f.Ecosystem), cell(f.Status), cell(f.Severity), cell(f.Priority))
		if f.Reason != "" {
			fmt.Fprintf(&b, "  - Why flagged: %s\n", cell(f.Reason))
		}
		if len(f.Fixed) > 0 {
			fmt.Fprintf(&b, "  - Fixed version: %s", cell(strings.Join(f.Fixed, ", ")))
			if f.FixedSource != "" {
				fmt.Fprintf(&b, " (%s)", cell(f.FixedSource))
			}
			b.WriteByte('\n')
		}
		if f.Recommendation != "" {
			fmt.Fprintf(&b, "  - Next step: %s\n", cell(f.Recommendation))
		}
		if f.Status == "affected" && f.Origin == "dpkg" {
			if names := binaryNames[f.Component+"\x00"+f.Version]; len(names) > 0 {
				fmt.Fprintf(&b, "  - Installed binary packages: %s\n", cell(strings.Join(names, ", ")))
			}
		}
		fmt.Fprintf(&b, "  - Advisories (%s): %s\n", cell(f.Source), cell(strings.Join(g.advisories, ", ")))
	}
	b.WriteString("\n")
	checked, unchecked := 0, 0
	for _, c := range r.Components {
		if c.Result == "NOT_CHECKED" || c.Result == "INCOMPLETE" {
			unchecked++
		} else {
			checked++
		}
	}
	containers := fmt.Sprint(len(r.Inventory.Containers))
	for _, n := range r.Coverage {
		if n.Source == "containers" && (n.Code == inventory.Unavailable || n.Code == inventory.Truncated || n.Code == inventory.NotChecked) {
			containers += " (incomplete; total unknown)"
			break
		}
	}
	fmt.Fprintf(&b, "\n## Coverage summary\n\nComponent queries completed: %d. Unchecked/incomplete components: %d. Local services: %d. Listening/bound sockets: %d. Running containers inventoried: %s.\n", checked, unchecked, len(r.Inventory.Services), len(r.Inventory.Listeners), containers)
	b.WriteString("\n## Listening ports and owners\n\nBindings do not prove Internet reachability. Wildcard/public-address binds need firewall/NAT review, especially management, database and monitoring services. No external probes were sent.\n\n| Protocol | Family | Port | Bind scope | Process | PID | Service | Reachability | Review |\n|---|---|---|---|---|---|---|---|---|\n")
	for _, l := range r.Inventory.Listeners {
		fmt.Fprintf(&b, "| %s | %s | %d | %s | %s | %d | %s | %s | %s |\n", cell(l.Protocol), cell(l.Family), l.Port, cell(l.BindScope), cell(l.Process), l.PID, cell(l.Service), cell(l.Reachability), cell(portReview(l.Port, l.BindScope)))
	}
	if len(r.Inventory.Firewall) > 0 {
		b.WriteString("\n## Local ingress firewall\n\nVerdicts apply to new inbound packets on the interface and destination shown. Internet reachability is independent.\n\n| Family | Interface | Destination | Port | Source range | Local verdict | Path | Evidence |\n|---|---|---|---|---|---|---|---|\n")
		for _, v := range r.Inventory.Firewall {
			sources := v.SourceFirst
			if v.SourceLast != v.SourceFirst {
				sources += " – " + v.SourceLast
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %d/%s | %s | %s | %s | %s |\n", cell(v.Family), cell(v.Interface), cell(v.Destination), v.Port, cell(v.Protocol), cell(sources), cell(v.Status), cell(v.Path), cell(v.Reason))
		}
	}
	b.WriteString("\n## Container published ports\n\n| Container | Image | Host port | Container port | Bind scope | Reachability |\n|---|---|---|---|---|---|\n")
	for _, c := range r.Inventory.Containers {
		for _, p := range c.Ports {
			fmt.Fprintf(&b, "| %s | %s | %d/%s | %s | %s | %s |\n", cell(c.Name), cell(c.Image), p.HostPort, cell(p.Protocol), cell(p.ContainerPort), cell(p.BindScope), cell(p.Reachability))
		}
	}
	b.WriteString("\n## Services\n\n| Service | Active | State | PID |\n|---|---|---|---|\n")
	for i, s := range r.Inventory.Services {
		if i >= 100 {
			break
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %d |\n", cell(s.Name), cell(s.Active), cell(s.State), s.PID)
	}
	if len(r.Inventory.Services) > 100 {
		fmt.Fprintf(&b, "\nShowing 100 of %d services; full list in report.json.\n", len(r.Inventory.Services))
	}
	b.WriteString("\n## Coverage limitations\n\n")
	for _, n := range r.Coverage {
		fmt.Fprintf(&b, "- %s / %s: %s\n", cell(n.Code), cell(n.Source), cell(n.Detail))
	}
	b.WriteString("\n## Inventoried components\n\n| Component | Installed | Origin | Ecosystem | Rules | Result | Reason |\n|---|---|---|---|---|---|---|\n")
	for _, c := range r.Components {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %d | %s | %s |\n", cell(c.Name), cell(c.Version), cell(c.Origin), cell(c.Ecosystem), c.Rules, cell(c.Result), cell(c.Reason))
	}
	return b.String()
}

func recommendation(ecosystem string) string {
	switch ecosystem {
	case "CPE":
		return "Review the linked vendor advisory and update this explicitly mapped product through its trusted installer/package manager; NVD interval boundaries are not guaranteed fixed versions."
	case "npm", "PyPI":
		return "Update the affected global language package through its trusted package manager to a supported fixed version; review the linked advisory."
	default:
		return "Update using the distribution's supported package repository; check vendor advisory and available fixed source version."
	}
}

func portReview(port int, scope string) string {
	if scope == "loopback" {
		return ""
	}
	services := map[int]string{2375: "Docker API", 2376: "Docker API", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 11211: "Memcached", 27017: "MongoDB", 9200: "Elasticsearch", 9090: "monitoring", 9100: "monitoring"}
	if service := services[port]; service != "" {
		return "Review source restrictions if this is " + service + "; Internet reachability is unknown"
	}
	return ""
}
