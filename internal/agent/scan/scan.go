// Package scan compares local inventory with a single authenticated disk
// publication. It contains no HTTP client and never updates installed software.
package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"shixpeer.com/ward/internal/agent/database"
	"shixpeer.com/ward/internal/atomicfile"
	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/internal/cpe"
	"shixpeer.com/ward/internal/productid"
	"shixpeer.com/ward/pkg/inventory"
)

const FormatVersion = 1
const maxFindings = 10000

type Finding struct {
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
	Name         string `json:"name"`
	Version      string `json:"version"`
	Ecosystem    string `json:"ecosystem,omitempty"`
	Origin       string `json:"origin"`
	Product      string `json:"product,omitempty"`
	MatchVersion string `json:"match_version,omitempty"`
	Reason       string `json:"reason,omitempty"`
	Rules        int    `json:"rules"`
	Result       string `json:"result"`
}
type Publication struct {
	Revision int64                    `json:"revision"`
	Created  time.Time                `json:"created_at"`
	Expires  time.Time                `json:"expires_at"`
	Profile  compactdb.Profile        `json:"profile"`
	Sources  []compactdb.SourceStatus `json:"sources"`
}
type Report struct {
	FormatVersion int                `json:"format_version"`
	GeneratedAt   time.Time          `json:"generated_at"`
	Offline       bool               `json:"offline"`
	Status        string             `json:"status"`
	Database      *Publication       `json:"database,omitempty"`
	Inventory     inventory.Snapshot `json:"inventory"`
	Components    []Component        `json:"components"`
	Findings      []Finding          `json:"findings"`
	Coverage      []inventory.Note   `json:"coverage"`
	Confirmed     int                `json:"confirmed"`
	Review        int                `json:"requires_review"`
}

func New(s inventory.Snapshot) Report {
	return Report{FormatVersion: FormatVersion, GeneratedAt: time.Now().UTC(), Offline: true, Status: "partial", Inventory: s, Components: components(s), Findings: []Finding{}, Coverage: append([]inventory.Note{}, s.Coverage...)}
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
func components(s inventory.Snapshot) []Component {
	out := []Component{}
	seen := map[string]bool{}
	add := func(c Component) {
		key := c.Ecosystem + "\x00" + c.Name + "\x00" + c.Version + "\x00" + c.Origin + "\x00" + c.Product + "\x00" + c.MatchVersion
		if !seen[key] {
			seen[key] = true
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
		}
		add(c)
	}
	for _, p := range s.Packages {
		c := Component{Name: p.Name, Version: p.Version, Origin: p.Manager}
		if p.Manager == "dpkg" && eco != "" {
			c.Ecosystem = eco
			if p.SourceName != "" {
				c.Name = p.SourceName
			}
			if p.SourceVersion != "" {
				c.Version = p.SourceVersion
			}
		}
		if p.Manager == "homebrew-formula" && p.Provenance == "homebrew/core" && p.UpstreamVersion != "" {
			if product := productid.Formula[p.Name]; product != "" {
				c.Ecosystem = "CPE"
				c.Product = product
				c.MatchVersion = p.UpstreamVersion
			}
		}
		if c.Ecosystem == "" {
			c.Reason = "no explicit supported upstream identity; custom taps and name guesses are not mapped"
		}
		add(c)
	}
	for _, a := range s.Applications {
		c := Component{Name: a.Name, Version: a.Version, Origin: "application-bundle", Reason: "bundle identifier has no explicit upstream mapping"}
		if product := productid.Bundle[a.Identifier]; product != "" && a.VersionKind == "release" {
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
	m := db.Manifest
	r.Database = &Publication{Revision: m.Revision, Created: m.CreatedAt, Expires: m.ExpiresAt, Profile: m.Profile, Sources: m.Sources}
	r.Components = components(r.Inventory)
	r.Coverage = append(r.Coverage, inventory.Note{Code: inventory.NotChecked, Source: "matching", Detail: "confirmed rules cover Debian/Ubuntu source packages and explicitly mapped simple NVD CPE products; unsupported identities/conditions and kernels without a supported loaded-version signature remain unchecked"})
	seenFindings := map[string]int{}
	for i := range r.Components {
		c := &r.Components[i]
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
					if format == cpe.RuleFormat {
						available = true
					}
				}
			}
			if !available {
				c.Result = "NOT_CHECKED"
				c.Reason = "installed publication predates indexed NVD CPE rules; refresh Beacon and update the agent database"
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
		err := db.Lookup(ctx, "p", compactdb.PackageKey(c.Ecosystem, queryName), 100000, func(raw []byte) error {
			var row compactdb.Row
			if e := json.Unmarshal(raw, &row); e != nil {
				return e
			}
			if row.Ecosystem != c.Ecosystem || row.Package != queryName {
				return fmt.Errorf("package index identity mismatch")
			}
			c.Rules++
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
					return err
				}
				if !found {
					return fmt.Errorf("missing exact version set")
				}
			}
			d := evaluate(row, version, exact)
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
			}
			if d.state == "excluded" {
				return nil
			}
			identity := queryName + "\x00" + version + "\x00" + c.Ecosystem + "\x00" + c.Name + "\x00" + c.Origin + "\x00" + c.Version + "\x00" + row.Source + "\x00" + row.ID
			if index, ok := seenFindings[identity]; ok {
				existing := &r.Findings[index]
				existing.RuleMatches++
				if existing.Status == "review" && d.state == "affected" {
					existing.Status = "affected"
					existing.Reason = d.reason
					existing.Evidence = row
					existing.Fixed = d.fixed
					existing.Recommendation = recommendation(c.Ecosystem)
					if c.Origin == "running-kernel" {
						existing.Recommendation = "Install the distribution security kernel and reboot into the fixed kernel; verify the loaded source version."
					}
					existing.Priority = priority(*existing)
					r.Review--
					r.Confirmed++
					c.Result = "AFFECTED"
				}
				return nil
			}
			if len(r.Findings) >= maxFindings {
				return fmt.Errorf("finding limit reached (%d); report is incomplete", maxFindings)
			}
			f := Finding{Evidence: row, Status: d.state, Component: c.Name, Version: c.Version, MatchVersion: version, Origin: c.Origin, RuleMatches: 1, Ecosystem: c.Ecosystem, Source: row.Source, ID: row.ID, Severity: "UNKNOWN", Fixed: d.fixed, Reason: d.reason}
			if err := enrich(ctx, db, &f); err != nil {
				return err
			}
			if f.Status == "affected" {
				r.Confirmed++
				c.Result = "AFFECTED"
				f.Recommendation = recommendation(c.Ecosystem)
				if c.Origin == "running-kernel" {
					f.Recommendation = "Install the distribution security kernel, schedule a reboot into the fixed kernel and verify its loaded source version; do not assume an installed update is already running."
				}
			} else {
				r.Review++
				if c.Result != "AFFECTED" {
					c.Result = "REQUIRES_REVIEW"
				}
				f.Recommendation = "Review the vendor advisory before treating this as an applicable vulnerability."
				if c.Ecosystem == "macOS" {
					f.Recommendation = "Check the linked Apple security bulletin and install the supported security update for this macOS branch."
				}
			}
			f.Priority = priority(f)
			seenFindings[identity] = len(r.Findings)
			r.Findings = append(r.Findings, f)
			return nil
		})
		if err != nil {
			c.Result = "INCOMPLETE"
			return err
		}
		if c.Rules > 0 && c.Result == "NO_ADVISORY_FOUND" {
			c.Result = "NO_MATCH_IN_AVAILABLE_RULES"
		}
	}
	if !m.ExpiresAt.After(time.Now()) {
		return fmt.Errorf("database expired during scan")
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if a.Component != b.Component {
			return a.Component < b.Component
		}
		return a.ID < b.ID
	})
	return nil
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
	b.WriteString("Offline scan. A missing advisory or zero findings does not mean this system is safe. Matching a vendor version rule does not prove runtime exploitability.\n\n")
	if r.Database != nil {
		fmt.Fprintf(&b, "Database revision: %d. Expires: %s. Profile: %s. Sources: %d.\n\n", r.Database.Revision, r.Database.Expires.Format(time.RFC3339), r.Database.Profile, len(r.Database.Sources))
	}
	if k := r.Inventory.RunningKernel; k != nil {
		fmt.Fprintf(&b, "## Running kernel\n\nRelease: %s. Status: %s. Loaded source: %s %s. Installed image source: %s. Reboot pending: %t. %s\n\n", cell(k.Release), cell(k.Status), cell(k.SourceName), cell(k.SourceVersion), cell(k.InstalledSourceVersion), k.RebootRequired, cell(k.Detail))
	}
	b.WriteString("## Findings\n\n| Priority | Status | Component | Installed | Advisory / source | Severity | Fixed version(s) |\n|---|---|---|---|---|---|---|\n")
	for i, f := range r.Findings {
		if i >= 100 {
			break
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s / %s | %s | %s |\n", cell(f.Priority), cell(f.Status), cell(f.Component), cell(f.Version), cell(f.ID), cell(f.Source), cell(f.Severity), cell(strings.Join(f.Fixed, ", ")))
	}

	if len(r.Findings) > 100 {
		fmt.Fprintf(&b, "\nShowing 100 of %d findings. Full findings, source IDs, references and per-finding evidence are in report.json.\n", len(r.Findings))
	}
	b.WriteString("\n## Recommended actions\n\n")
	seen := map[string]bool{}
	for _, f := range r.Findings {
		key := f.Component + "\x00" + f.Version + "\x00" + f.Status + "\x00" + f.Source
		if seen[key] {
			continue
		}
		seen[key] = true
		fmt.Fprintf(&b, "- **%s %s** (%s, %s): %s\n", cell(f.Component), cell(f.Version), cell(f.Status), cell(f.Source), cell(f.Recommendation))
	}
	checked, unchecked := 0, 0
	for _, c := range r.Components {
		if c.Result == "NOT_CHECKED" || c.Result == "INCOMPLETE" {
			unchecked++
		} else {
			checked++
		}
	}
	fmt.Fprintf(&b, "\n## Coverage summary\n\nComponent queries completed: %d. Unchecked/incomplete components: %d. Local services: %d. Listening/bound sockets: %d. Running containers inventoried: %d.\n", checked, unchecked, len(r.Inventory.Services), len(r.Inventory.Listeners), len(r.Inventory.Containers))
	b.WriteString("\n## Listening ports and owners\n\nBindings do not prove Internet reachability. Wildcard/public-address binds need firewall/NAT review, especially management, database and monitoring services. No external probes were sent.\n\n| Protocol | Family | Port | Bind scope | Process | PID | Service | Reachability | Review |\n|---|---|---|---|---|---|---|---|---|\n")
	for _, l := range r.Inventory.Listeners {
		fmt.Fprintf(&b, "| %s | %s | %d | %s | %s | %d | %s | %s | %s |\n", cell(l.Protocol), cell(l.Family), l.Port, cell(l.BindScope), cell(l.Process), l.PID, cell(l.Service), cell(l.Reachability), cell(portReview(l.Port, l.BindScope)))
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
