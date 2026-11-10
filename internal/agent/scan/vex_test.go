package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"shixpeer.com/ward/internal/agent/database"
	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/pkg/inventory"
)

func TestVEXContinuesAfterPackageErrorAndHandlesLargeKernelIndex(t *testing.T) {
	ctx := context.Background()
	const eco = "Ubuntu:22.04:LTS"
	const cve = "CVE-2099-90001"
	const kernel = "5.15.0-202.212"
	rows := []compactdb.Row{
		{Source: "canonical-osv", ID: "UBUNTU-" + cve, Ecosystem: eco, Package: "broken", Versions: []string{"1"}},
		{Source: "canonical-osv", ID: "UBUNTU-" + cve, Ecosystem: eco, Package: "linux", Versions: []string{kernel}},
		{Source: "ubuntu-vex", ID: "invalid-id", Ecosystem: compactdb.UbuntuVEX, Package: "broken@1/jammy"},
		{Source: "ubuntu-vex", ID: "UBUNTU-VEX-" + cve, Ecosystem: compactdb.UbuntuVEX, Package: "linux@" + kernel + "/jammy", Context: json.RawMessage(`{"status":"affected"}`)},
	}
	for i := range 100001 {
		rows = append(rows, compactdb.Row{
			Source: "ubuntu-vex", ID: fmt.Sprintf("UBUNTU-VEX-CVE-2098-%05d", i), Ecosystem: compactdb.UbuntuVEX,
			Package: "linux@" + kernel + "/jammy", Context: json.RawMessage(`{"status":"under_investigation"}`),
		})
	}
	dir, key := fixture(t, false, rows...)
	db, err := database.OpenReader(ctx, dir, key)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.Manifest.Sources[0].RuleFormats = append(db.Manifest.Sources[0].RuleFormats, compactdb.UbuntuVEX)
	r := New(inventory.Snapshot{
		Host: inventory.Host{Release: map[string]string{"ID": "ubuntu", "VERSION_ID": "22.04", "VERSION_CODENAME": "jammy"}},
		Packages: []inventory.Package{
			{Manager: "dpkg", Name: "broken", Version: "1"},
			{Manager: "dpkg", Name: "linux", Version: kernel},
		},
	})
	if err := Run(ctx, &r, db); err != nil {
		t.Fatal(err)
	}
	if r.VEXResolved != 1 || r.Review != 1 || r.Confirmed != 1 {
		t.Fatalf("resolved=%d review=%d confirmed=%d", r.VEXResolved, r.Review, r.Confirmed)
	}
	if r.ReviewReasons["Ubuntu VEX lookup failed for this package"] != 1 {
		t.Fatalf("review reasons: %v", r.ReviewReasons)
	}
	for _, f := range r.Findings {
		if f.Component == "linux" && (f.Status != "affected" || len(f.Fixed) != 0 || !strings.Contains(f.Reason, "no fixed version")) {
			t.Fatalf("unexpected affected finding: %+v", f)
		}
	}
	if md := Markdown(r); !strings.Contains(md, "broken 1 (Ubuntu:22.04:LTS, dpkg): invalid Ubuntu VEX index row") {
		t.Fatal("report lacks the failed product identity and error")
	}
}

func TestUbuntuReviewReasonsDistinguishVendorEvidence(t *testing.T) {
	reasons := map[string]bool{}
	for _, status := range []string{"", "under_investigation", "conflict"} {
		reason := ubuntuReviewReason(true, "", false, status)
		if reason == "" || reasons[reason] || resolveVEX(status).state != "" {
			t.Fatalf("status %q: %q", status, reason)
		}
		reasons[reason] = true
	}
}

func TestVEXIdentityForLegacyUbuntuContainer(t *testing.T) {
	release := map[string]string{"ID": "ubuntu", "VERSION_ID": "14.04"}
	product, issue := vexProduct("Ubuntu:14.04:LTS", release, "acl", "2.2.52-1")
	if product != "acl@2.2.52-1/trusty" || issue != "" {
		t.Fatalf("product=%q issue=%q", product, issue)
	}
	product, issue = vexProduct("Ubuntu:14.04:LTS", release, "acl", "")
	if product != "" || !strings.Contains(issue, "source package version") {
		t.Fatalf("product=%q issue=%q", product, issue)
	}
	product, issue = vexProduct("Ubuntu:28.04:LTS", map[string]string{"ID": "ubuntu", "VERSION_ID": "28.04"}, "acl", "1")
	if product != "" || !strings.Contains(issue, "VERSION_CODENAME") {
		t.Fatalf("product=%q issue=%q", product, issue)
	}
}

func TestVEXDeferredFixIsAffectedWithoutFixedVersion(t *testing.T) {
	d := resolveVEX("affected_fix_deferred")
	if d.state != "affected" || len(d.fixed) != 0 || !strings.Contains(d.reason, "deferred") {
		t.Fatalf("unexpected decision: %+v", d)
	}
}
