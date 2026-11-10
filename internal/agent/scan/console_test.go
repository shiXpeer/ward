package scan

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode"

	"shixpeer.com/ward/pkg/inventory"
)

func renderConsole(t *testing.T, r Report) string {
	t.Helper()
	var b bytes.Buffer
	if err := Console(&b, r, "/private/report.json", "/private/report.md"); err != nil {
		t.Fatal(err)
	}
	return b.String()
}
func TestConsoleCountsAndPriorityKeepCoverageHonest(t *testing.T) {
	r := Report{Status: "partial", Confirmed: 3, Review: 2, Components: []Component{{Result: "AFFECTED"}, {Result: "REQUIRES_REVIEW"}, {Result: "NO_ADVISORY_FOUND"}, {Result: "NOT_CHECKED"}, {Result: "INCOMPLETE"}}, Findings: []Finding{
		{Status: "affected", Component: "z-high", Version: "1.0", ID: "CVE-HIGH", Severity: "HIGH"},
		{Status: "affected", Component: "a-known", Version: "2.0", ID: "CVE-KNOWN", Severity: "MEDIUM", KnownExploited: true, Fixed: []string{"2.1"}},
		{Status: "affected", Component: "z-high", Version: "1.0", ID: "CVE-CRITICAL", Severity: "CRITICAL"},
		{Status: "review", Component: "uncertain", Version: "3.0", Reason: "unsupported applicability"},
		{Status: "review", Component: "a-known", Version: "2.0", Reason: "another source needs review"},
	}}
	text := renderConsole(t, r)
	for _, want := range []string{"5 total | 3 checked | 1 not checked | 1 incomplete", "2 affected components shown (3 version-rule matches total)", "1 components with review-only result", "2 records total", "KNOWN EXPLOITED", "Fixed version: 2.1", "2 total · 1 CRITICAL · 1 HIGH", "applicability is uncertain", "/private/report.md"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q:\n%s", want, text)
		}
	}
	if strings.Count(text, "z-high 1.0") != 1 || strings.Contains(text, "CVE-CRITICAL") || strings.Index(text, "a-known 2.0") < strings.Index(text, "z-high 1.0") {
		t.Fatal("critical severity did not come first")
	}
}
func TestConsoleBoundsAndSanitizesTerminalMetadata(t *testing.T) {
	r := Report{Status: "partial", Confirmed: 20}
	for i := 0; i < 20; i++ {
		r.Findings = append(r.Findings, Finding{Status: "affected", Component: fmt.Sprintf("component-%02d\x1b[31m\nFAKE\r\u202e", i), Version: "1.0", Severity: "MEDIUM", ID: "CVE-test"})
	}
	for i := 0; i < 20; i++ {
		r.Coverage = append(r.Coverage, inventory.Note{Code: inventory.Unavailable, Source: fmt.Sprint(i), Detail: "warning\x1b]8;;https://invalid\a\nspoof"})
	}
	text := renderConsole(t, r)
	if !strings.Contains(text, "12 more lower-severity affected components") || !strings.Contains(text, "15 more warnings") {
		t.Fatal(text)
	}
	if strings.Count(text, "Advisories: 1 total") != consoleFindings || strings.Count(text, "  [!]") != consoleWarnings {
		t.Fatal("unbounded output", text)
	}
	for _, r := range text {
		if r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
			t.Fatalf("terminal control survived: %U", r)
		}
	}
	if strings.Contains(text, "\nFAKE") || strings.Contains(text, "\nspoof") {
		t.Fatal("metadata injected a line")
	}
}
func TestConsoleZeroAndIncompleteAreNotClean(t *testing.T) {
	text := renderConsole(t, Report{Status: "incomplete", Components: []Component{{Result: "NOT_CHECKED"}}, Coverage: []inventory.Note{{Code: inventory.Unavailable, Source: "database-scan", Detail: "expired publication"}}})
	for _, want := range []string{"[ERROR] Scan incomplete", "0 checked", "not a clean bill of health", "expired publication"} {
		if !strings.Contains(text, want) {
			t.Fatal(want, text)
		}
	}
}
func TestConsoleWarnsAboutBindingsWithoutClaimingExposure(t *testing.T) {
	r := Report{Status: "partial", Inventory: inventory.Snapshot{Listeners: []inventory.Listener{{Protocol: "tcp", Port: 9100, BindScope: "wildcard", Process: "exporter"}, {Protocol: "tcp", Port: 6379, BindScope: "loopback", Process: "redis"}}}}
	text := renderConsole(t, r)
	if !strings.Contains(text, "tcp/9100 wildcard") || !strings.Contains(text, "Internet reachability is unknown") {
		t.Fatal(text)
	}
	if strings.Contains(text, "tcp/6379") {
		t.Fatal("loopback listener incorrectly warned", text)
	}
}

type brokenConsole struct{}

func (brokenConsole) Write([]byte) (int, error) { return 0, errors.New("closed output") }
func TestConsolePropagatesOutputFailure(t *testing.T) {
	if err := Console(brokenConsole{}, Report{}, "", ""); err == nil {
		t.Fatal("output failure swallowed")
	}
}

func TestRunningKernelAndPendingRebootVisible(t *testing.T) {
	r := Report{Status: "partial", Inventory: inventory.Snapshot{RunningKernel: &inventory.Kernel{Release: "6.8.0-45-generic", SourceVersion: "6.8.0-45.45", Status: "IDENTIFIED", RebootRequired: true}}, Coverage: []inventory.Note{{Code: inventory.Unresolved, Source: "kernel-reboot", Detail: "newer kernel installed"}}}
	text := renderConsole(t, r)
	for _, want := range []string{"Kernel: 6.8.0-45-generic", "loaded source: 6.8.0-45.45", "REBOOT PENDING", "kernel-reboot: newer kernel installed"} {
		if !strings.Contains(text, want) {
			t.Fatal(want, text)
		}
	}
}

func TestConsoleSummarizesUrgentAdvisoriesAndSortsLowerSeverity(t *testing.T) {
	r := Report{}
	for i := range 12 {
		r.Findings = append(r.Findings, Finding{Status: "affected", Component: "shared", Severity: "HIGH", ID: fmt.Sprintf("CVE-HIGH-%02d", i), Reason: "Installed version is in the affected range"})
	}
	r.Findings = append(r.Findings,
		Finding{Status: "affected", Component: "a-low", Severity: "LOW", ID: "CVE-LOW"},
		Finding{Status: "affected", Component: "z-medium", Severity: "MEDIUM", ID: "CVE-MEDIUM"},
	)
	text := renderConsole(t, r)
	if strings.Contains(text, "CVE-HIGH-") || !strings.Contains(text, "Advisories: 12 total · 0 CRITICAL · 12 HIGH (see full report).") || strings.Count(text, "Why flagged: Installed version is in the affected range.") != 1 ||
		strings.Index(text, "[MEDIUM] z-medium") > strings.Index(text, "[LOW] a-low") {
		t.Fatal(text)
	}
}

func TestMarkdownCombinesGuidanceAcrossSeverities(t *testing.T) {
	first := Finding{Status: "affected", Component: "linux", Version: "1", Origin: "dpkg",
		Severity: "HIGH", ID: "CVE-FIRST", Reason: "vendor marks this version affected", Recommendation: "Check updates"}
	second := first
	second.ID, second.Severity = "CVE-SECOND", "MEDIUM"
	container := first
	container.ID, container.Origin = "CVE-CONTAINER", "docker:test"
	text := Markdown(Report{Findings: []Finding{first, second, container}})
	if strings.Count(text, "Why flagged: vendor marks this version affected") != 2 ||
		!strings.Contains(text, "CVE-FIRST (HIGH), CVE-SECOND (MEDIUM)") ||
		!strings.Contains(text, "docker:test") {
		t.Fatal(text)
	}
}
