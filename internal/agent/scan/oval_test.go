package scan

import (
	"context"
	"encoding/json"
	"testing"

	"shixpeer.com/ward/internal/agent/database"
	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/pkg/inventory"
)

func TestJammyOVALResolvesOnlyMatchingRunningKernel(t *testing.T) {
	ctx := context.Background()
	const eco = "Ubuntu:22.04:LTS"
	const version = "5.15.0-198.208"
	const id = "CVE-2099-90001"
	dir, key := fixture(t, false,
		compactdb.Row{Source: "canonical-osv", ID: "UBUNTU-" + id, Ecosystem: eco, Package: "linux", Versions: []string{version}},
		compactdb.Row{Source: "ubuntu-oval-jammy", ID: id, Ecosystem: compactdb.UbuntuJammyOVAL, Package: "linux", Context: json.RawMessage(`{"pattern":"5\\.15\\.0-[0-9]+-generic"}`)},
	)
	db, err := database.OpenReader(ctx, dir, key)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.Manifest.Sources[0].RuleFormats = append(db.Manifest.Sources[0].RuleFormats, compactdb.UbuntuJammyOVAL)
	snapshot := inventory.Snapshot{
		Host:          inventory.Host{Release: map[string]string{"ID": "ubuntu", "VERSION_ID": "22.04", "VERSION_CODENAME": "jammy"}},
		Packages:      []inventory.Package{{Manager: "dpkg", Name: "linux", Version: version}},
		RunningKernel: &inventory.Kernel{Status: "IDENTIFIED", Release: "5.15.0-198-generic", SourceName: "linux", SourceVersion: version},
	}
	for _, tc := range []struct {
		release           string
		confirmed, review int
	}{{"5.15.0-198-generic", 1, 1}, {"6.8.0-198-generic", 0, 2}} {
		snapshot.RunningKernel.Release = tc.release
		r := New(snapshot)
		if err := Run(ctx, &r, db); err != nil {
			t.Fatal(err)
		}
		if r.Confirmed != tc.confirmed || r.Review != tc.review {
			t.Fatalf("%s: confirmed=%d review=%d", tc.release, r.Confirmed, r.Review)
		}
		for _, f := range r.Findings {
			if f.Status == "affected" && f.Origin != "running-kernel" {
				t.Fatalf("OVAL affected finding for an unloaded package: %+v", f)
			}
		}
	}
}
