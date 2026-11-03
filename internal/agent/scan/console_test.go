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
	for _, want := range []string{"5 total | 3 checked | 1 not checked | 1 incomplete", "2 affected components (3 version-rule matches)", "1 components with review-only result", "2 records", "KNOWN EXPLOITED", "Fixed version for this example: 2.1", "2 matches; example: CVE-CRITICAL", "applicability is uncertain", "/private/report.md"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q:\n%s", want, text)
		}
	}
	if strings.Index(text, "a-known 2.0") > strings.Index(text, "z-high 1.0") {
		t.Fatal("known exploited did not come first")
	}
}
func TestConsoleBoundsAndSanitizesTerminalMetadata(t *testing.T) {
	r := Report{Status: "partial", Confirmed: 20}
	for i := 0; i < 20; i++ {
		r.Findings = append(r.Findings, Finding{Status: "affected", Component: fmt.Sprintf("component-%02d\x1b[31m\nFAKE\r\u202e", i), Version: "1.0", Severity: "HIGH", ID: "CVE-test"})
	}
	for i := 0; i < 20; i++ {
		r.Coverage = append(r.Coverage, inventory.Note{Code: inventory.Unavailable, Source: fmt.Sprint(i), Detail: "warning\x1b]8;;https://invalid\a\nspoof"})
	}
	text := renderConsole(t, r)
	if !strings.Contains(text, "12 more affected components") || !strings.Contains(text, "15 more warnings") {
		t.Fatal(text)
	}
	if strings.Count(text, "example: CVE-test") != consoleFindings || strings.Count(text, "  [!]") != consoleWarnings {
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
