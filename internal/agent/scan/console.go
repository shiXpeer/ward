package scan

import (
	"fmt"
	"io"
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
		if priority(f) < priority(g.example) || priority(f) == priority(g.example) && f.ID < g.example.ID {
			g.example = f
		}
	}
	out := make([]consoleGroup, 0, len(groups))
	for _, g := range groups {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if priority(a.example) != priority(b.example) {
			return priority(a.example) < priority(b.example)
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

// Console prints bounded plain text that is safe for terminals, pipes and logs.
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
	affected := consoleGroups(r.Findings, "affected")
	review := consoleGroups(r.Findings, "review")
	fmt.Fprintf(&b, "Findings: %d affected components (%d version-rule matches)\n", len(affected), r.Confirmed)
	fmt.Fprintf(&b, "Review: %d components with review-only result | %d components with review records (%d records)\n", doubtful, len(review), r.Review)
	if r.Status == "incomplete" {
		b.WriteString("[ERROR] Scan incomplete. Findings and counts may be partial.\n")
	}
	if len(affected) > 0 {
		b.WriteString("\nFINDINGS — highest priority first\n")
		for i, g := range affected {
			if i >= consoleFindings {
				break
			}
			f := g.example
			label := strings.ToUpper(f.Severity)
			if label == "" {
				label = "UNKNOWN"
			}
			if f.KnownExploited {
				label = "KNOWN EXPLOITED / " + label
			}
			fmt.Fprintf(&b, "  [%s] %s %s (%s) — %d matches; example: %s\n", terminalText(label, 48), terminalText(g.name, 64), terminalText(g.version, 48), terminalText(g.origin, 32), g.count, terminalText(f.ID, 96))
			if len(f.Fixed) > 0 {
				fmt.Fprintf(&b, "    Fixed version for this example: %s\n", terminalText(strings.Join(f.Fixed, ", "), 100))
			}
		}
		if len(affected) > consoleFindings {
			fmt.Fprintf(&b, "  ... %d more affected components in the full report\n", len(affected)-consoleFindings)
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
