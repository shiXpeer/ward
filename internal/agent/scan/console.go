package scan

import (
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"unicode"
)

const consoleFindings = 8
const consoleReviews = 3
const consoleWarnings = 5

type consoleGroup struct {
	name, version, origin string
	count                 int
	example               Finding
	advisories            []string
	severityCounts        [2]int
	exploited             bool
}

func sortedReviewReasons(counts map[string]int) []string {
	reasons := make([]string, 0, len(counts))
	for reason := range counts {
		reasons = append(reasons, reason)
	}
	sort.Slice(reasons, func(i, j int) bool {
		if counts[reasons[i]] != counts[reasons[j]] {
			return counts[reasons[i]] > counts[reasons[j]]
		}
		return reasons[i] < reasons[j]
	})
	return reasons
}

func severityRank(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	case "NEGLIGIBLE":
		return 4
	default:
		return 5
	}
}

func urgentFinding(f Finding) bool {
	return f.Status == "affected" && (f.KnownExploited || severityRank(f.Severity) <= 1)
}

func consoleFindingLess(a, b Finding) bool {
	if severityRank(a.Severity) != severityRank(b.Severity) {
		return severityRank(a.Severity) < severityRank(b.Severity)
	}
	if a.KnownExploited != b.KnownExploited {
		return a.KnownExploited
	}
	return findingLess(a, b)
}

func writeConsoleFinding(b *strings.Builder, g consoleGroup) {
	f := g.example
	label := strings.ToUpper(f.Severity)
	if label == "" {
		label = "UNKNOWN"
	}
	if g.exploited {
		label = "KNOWN EXPLOITED / " + label
	}
	fmt.Fprintf(b, "  [%s] %s %s (%s)\n", terminalText(label, 48), terminalText(f.Component, 64), terminalText(f.Version, 48), terminalText(f.Origin, 48))
	if f.Reason != "" {
		fmt.Fprintf(b, "    Why flagged: %s.\n", terminalText(strings.TrimRight(f.Reason, "."), 220))
	}
	if len(f.Fixed) > 0 {
		fmt.Fprintf(b, "    Fixed version: %s\n", terminalText(strings.Join(f.Fixed, ", "), 120))
	} else {
		b.WriteString("    Fixed version: unavailable in the matched advisory data.\n")
	}
	if f.Recommendation != "" {
		fmt.Fprintf(b, "    Next step: %s\n", terminalText(f.Recommendation, 220))
	}
	fmt.Fprintf(b, "    Advisories: %d total · %d CRITICAL · %d HIGH (see full report).\n", g.count, g.severityCounts[0], g.severityCounts[1])
}

func guidanceAdvisory(f Finding, withSeverity bool) string {
	if withSeverity {
		return f.ID + " (" + f.Severity + ")"
	}
	return f.ID
}

func groupGuidance(findings []Finding, combineSeverity bool) []consoleGroup {
	type guidance struct {
		component, version, origin, ecosystem, reason, fixed, next, status, source, fixedSource string
		severity                                                                                int
		exploited                                                                               bool
	}
	grouped := map[guidance]int{}
	shown := []consoleGroup{}
	for _, f := range findings {
		key := guidance{f.Component, f.Version, f.Origin, f.Ecosystem, f.Reason, strings.Join(f.Fixed, ", "), f.Recommendation, f.Status, f.Source, f.FixedSource, severityRank(f.Severity), f.KnownExploited}
		if combineSeverity {
			key.severity = 0
		}
		if i, ok := grouped[key]; ok {
			if consoleFindingLess(f, shown[i].example) {
				shown[i].example = f
			}
			shown[i].advisories = append(shown[i].advisories, guidanceAdvisory(f, combineSeverity))
			continue
		}
		grouped[key] = len(shown)
		shown = append(shown, consoleGroup{example: f, count: 1, advisories: []string{guidanceAdvisory(f, combineSeverity)}})
	}
	for i := range shown {
		sort.Strings(shown[i].advisories)
		shown[i].advisories = slices.Compact(shown[i].advisories)
	}
	return shown
}

func consoleGroups(findings []Finding, status string) []consoleGroup {
	groups := map[string]*consoleGroup{}
	for _, f := range findings {
		if f.Status != status {
			continue
		}
		key := f.Component + "\x00" + f.Version + "\x00" + f.Origin + "\x00" + f.Ecosystem
		g := groups[key]
		if g == nil {
			g = &consoleGroup{name: f.Component, version: f.Version, origin: f.Origin, example: f}
			groups[key] = g
		}
		g.count++
		if rank := severityRank(f.Severity); rank < len(g.severityCounts) {
			g.severityCounts[rank]++
		}
		g.exploited = g.exploited || f.KnownExploited
		if consoleFindingLess(f, g.example) {
			g.example = f
		}
	}
	out := make([]consoleGroup, 0, len(groups))
	for _, g := range groups {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.example.KnownExploited != b.example.KnownExploited || severityRank(a.example.Severity) != severityRank(b.example.Severity) {
			return consoleFindingLess(a.example, b.example)
		}
		if a.name != b.name {
			return a.name < b.name
		}
		if a.version != b.version {
			return a.version < b.version
		}
		return a.origin < b.origin
	})
	return out
}

// Console prints sanitized plain text that is safe for terminals, pipes and logs.
// Counts distinguish completed component queries from matched advisory records;
// missing coverage never becomes a claim that the host is safe.
func Console(w io.Writer, r Report, jsonPath, markdownPath string) error {
	var b strings.Builder
	checked, unchecked, incomplete, doubtful := 0, 0, 0, 0
	for _, c := range r.Components {
		switch c.Result {
		case "NOT_CHECKED":
			unchecked++
		case "INCOMPLETE":
			incomplete++
		case "REQUIRES_REVIEW":
			checked++
			doubtful++
		case "AFFECTED", "NO_ADVISORY_FOUND", "NO_MATCH_IN_AVAILABLE_RULES":
			checked++
		default:
			unchecked++
		}
	}
	fmt.Fprintf(&b, "\nShixpeer Ward | offline scan | %s\n", terminalText(r.Status, 32))
	fmt.Fprintf(&b, "Components: %d total | %d checked | %d not checked | %d incomplete\n", len(r.Components), checked, unchecked, incomplete)
	if k := r.Inventory.RunningKernel; k != nil {
		loaded := k.SourceVersion
		if loaded == "" {
			loaded = "unknown"
		}
		boot := ""
		if k.RebootRequired {
			boot = " | REBOOT PENDING"
		}
		fmt.Fprintf(&b, "Kernel: %s | loaded source: %s | %s%s\n", terminalText(k.Release, 64), terminalText(loaded, 64), terminalText(k.Status, 24), boot)
	}
	if r.OmittedFindings > 0 {
		fmt.Fprintf(&b, "Finding details omitted: %d (included in totals)\n", r.OmittedFindings)
	}
	affected := consoleGroups(r.Findings, "affected")
	review := consoleGroups(r.Findings, "review")
	fmt.Fprintf(&b, "Findings: %d affected components shown (%d version-rule matches total)\n", len(affected), r.Confirmed)
	fmt.Fprintf(&b, "Review: %d components with review-only result | %d components shown with review records (%d records total)\n", doubtful, len(review), r.Review)
	for _, scope := range sortedReviewReasons(r.ReviewScopes) {
		fmt.Fprintf(&b, "  %s — %d review records\n", scope, r.ReviewScopes[scope])
	}

	for _, reason := range sortedReviewReasons(r.ReviewReasons) {
		fmt.Fprintf(&b, "  %d — %s\n", r.ReviewReasons[reason], terminalText(reason, 220))
	}

	if r.VEXResolved > 0 {
		fmt.Fprintf(&b, "Ubuntu VEX: %d ambiguous applicability records resolved\n", r.VEXResolved)
	}
	if len(r.Inventory.Firewall) > 0 {
		verdicts := map[string]int{}
		for _, entry := range r.Inventory.Firewall {
			verdicts[entry.Status]++
		}
		fmt.Fprintf(&b, "Local ingress: %d allowed | %d blocked | %d unknown entries (see report)\n", verdicts["ALLOWED"], verdicts["BLOCKED"], verdicts["UNKNOWN"])
	}
	if r.Status == "incomplete" {
		b.WriteString("[ERROR] Scan incomplete. Findings and counts may be partial.\n")
	}
	if len(affected) > 0 {
		b.WriteString("\nFINDINGS — highest priority first\n")
		shownLower, omitted := 0, 0
		for _, group := range affected {
			urgent := group.exploited || group.severityCounts[0]+group.severityCounts[1] > 0
			if !urgent && shownLower >= consoleFindings {
				omitted++
				continue
			}
			if !urgent {
				shownLower++
			}
			writeConsoleFinding(&b, group)
		}
		if omitted > 0 {
			fmt.Fprintf(&b, "  ... %d more lower-severity affected components in the full report\n", omitted)
		}
	} else {
		b.WriteString("\nNo confirmed version-rule matches in the checked coverage. This is not a clean bill of health.\n")
	}
	if len(review) > 0 {
		b.WriteString("\nREQUIRES REVIEW — applicability is uncertain\n")
		for i, g := range review {
			if i >= consoleReviews {
				break
			}
			fmt.Fprintf(&b, "  [?] %s %s — %d records; %s\n", terminalText(g.name, 64), terminalText(g.version, 48), g.count, terminalText(g.example.Reason, 120))
		}
		if len(review) > consoleReviews {
			fmt.Fprintf(&b, "  ... %d more components with review records in the full report\n", len(review)-consoleReviews)
		}
	}
	warnings := []string{}
	seen := map[string]bool{}
	add := func(s string) {
		s = terminalText(s, 180)
		if !seen[s] {
			seen[s] = true
			warnings = append(warnings, s)
		}
	}
	// Probe/database failures take precedence over routine scope notes.
	for _, code := range []string{"UNAVAILABLE", "TRUNCATED"} {
		for _, n := range r.Coverage {
			if n.Code == code {
				add(n.Source + ": " + n.Detail)
			}
		}
	}
	for _, n := range r.Coverage {
		if n.Source == "kernel-reboot" || n.Source == "running-kernel" {
			add(n.Source + ": " + n.Detail)
		}
	}
	for _, l := range r.Inventory.Listeners {
		if advice := portReview(l.Port, l.BindScope); advice != "" {
			add(fmt.Sprintf("%s/%d %s (%s): %s", l.Protocol, l.Port, l.BindScope, l.Process, advice))
		}
	}
	for _, c := range r.Inventory.Containers {
		for _, p := range c.Ports {
			if advice := portReview(p.HostPort, p.BindScope); advice != "" {
				add(fmt.Sprintf("container %s %s/%d %s: %s", c.Name, p.Protocol, p.HostPort, p.BindScope, advice))
			}
		}
	}
	if unchecked > 0 {
		add(fmt.Sprintf("%d components lack supported identity/version/coverage; see per-component reasons", unchecked))
	}
	for _, n := range r.Coverage {
		if n.Code == "NOT_CHECKED" || n.Code == "UNRESOLVED" {
			add(n.Source + ": " + n.Detail)
		}
	}
	if len(warnings) > 0 {
		fmt.Fprintf(&b, "\nWARNINGS (%d)\n", len(warnings))
		for i, s := range warnings {
			if i >= consoleWarnings {
				break
			}
			fmt.Fprintf(&b, "  [!] %s\n", s)
		}
		if len(warnings) > consoleWarnings {
			fmt.Fprintf(&b, "  ... %d more warnings; see the full report and coverage limits\n", len(warnings)-consoleWarnings)
		}
	}
	b.WriteString("\nVersion-rule matches do not demonstrate exploitability. No system changes were made.\n")
	fmt.Fprintf(&b, "Report: %s\nJSON:   %s\n", terminalText(markdownPath, 1024), terminalText(jsonPath, 1024))
	_, err := io.WriteString(w, b.String())
	return err
}

func terminalText(s string, limit int) string {
	out := make([]rune, 0, min(len(s), limit))
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.IsSpace(r) {
			r = ' '
		}
		if len(out) >= limit {
			return strings.TrimSpace(string(out)) + "…"
		}
		out = append(out, r)
	}
	return strings.TrimSpace(string(out))
}
