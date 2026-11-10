package source

import (
	"slices"
	"strings"
	"testing"
)

func TestUbuntuOSVPriorityAndCVEShortAlias(t *testing.T) {
	a, err := parseOSV([]byte(`{"id":"UBUNTU-CVE-2026-1234","modified":"2026-11-03T00:00:00Z","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N"},{"type":"Ubuntu","score":"high"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if a.Severity != "HIGH" || !slices.Contains(a.Aliases, "CVE-2026-1234") {
		t.Fatal(a)
	}
}

func TestVEXRequiresExactSourceProductAndDistro(t *testing.T) {
	const doc = `{"statements":[{"products":[
		{"@id":"pkg:deb/ubuntu/example@1%3A2-1?arch=source&distro=jammy"},
		{"@id":"pkg:deb/ubuntu/example@1%3A2-1?arch=arm64&distro=jammy"},
		{"@id":"pkg:deb/ubuntu/example@1%3A2-1?arch=source"}],
		"vulnerability":{"name":"CVE-2099-90001"},"status":"affected"}]}`
	a, err := parseUbuntuVEX("CVE-2099-90001", strings.NewReader(doc))
	if err != nil || len(a.Affected) != 1 || a.Affected[0].Name != "example@1:2-1/jammy" {
		t.Fatalf("advisory=%+v error=%v", a, err)
	}
}

func TestVEXSeparatesDeferredFixFromPendingTriage(t *testing.T) {
	const doc = `{"statements":[
		{"vulnerability":{"name":"CVE-2099-90001"},"products":[{"@id":"pkg:deb/ubuntu/linux@1?arch=source&distro=jammy"}],"status":"under_investigation","status_notes":"This package (for the given release) is vulnerable to the CVE, the problem is understood, but it is currently deferred. CVE Notes / justification: no upstream fix."},
		{"vulnerability":{"name":"CVE-2099-90001"},"products":[{"@id":"pkg:deb/ubuntu/linux@2?arch=source&distro=noble"}],"status":"under_investigation","status_notes":"Vulnerability assessment is pending."}
	]}`
	a, err := parseUbuntuVEX("CVE-2099-90001", strings.NewReader(doc))
	if err != nil || len(a.Affected) != 2 ||
		string(a.Affected[0].EcosystemSpecific) != `{"status":"affected_fix_deferred"}` ||
		string(a.Affected[1].EcosystemSpecific) != `{"status":"under_investigation"}` {
		t.Fatalf("advisory=%+v error=%v", a, err)
	}
}
