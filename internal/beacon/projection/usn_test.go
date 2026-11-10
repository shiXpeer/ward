package projection

import (
	"encoding/json"
	"slices"
	"testing"

	"shixpeer.com/ward/internal/beacon/source"
	"shixpeer.com/ward/internal/compactdb"
)

func TestCanonicalUSNUsesPackageScopedCVEs(t *testing.T) {
	const jammy = "Ubuntu:22.04:LTS"
	const cve = "CVE-2099-10001"
	pkg := source.Affected{
		Ecosystem: jammy, Name: "first",
		EcosystemSpecific: json.RawMessage(`{"availability":"No subscription required","binaries":[{"binary_name":"first"}]}`),
		DatabaseSpecific:  json.RawMessage(`{"cves_map":{"ecosystem":"Ubuntu:22.04:LTS","cves":[{"id":"CVE-2099-10001","severity":[{"type":"Ubuntu","score":"medium"}]},{"id":"CVE-2099-10001"},{"id":"CVE-2099-99999"}]}}`),
	}
	unscoped := pkg
	unscoped.Name, unscoped.DatabaseSpecific = "unscoped", nil
	wrongRelease := pkg
	wrongRelease.Name, wrongRelease.Ecosystem = "wrong-release", "Ubuntu:24.04:LTS"
	subscription := pkg
	subscription.Name = "subscription"
	subscription.EcosystemSpecific = json.RawMessage(`{"availability":"Available with Ubuntu Pro"}`)
	unsupported := pkg
	unsupported.Name = "unsupported"
	unsupported.DatabaseSpecific = json.RawMessage(`{"cves_map":{"ecosystem":"Ubuntu:22.04:LTS","cves":[{"id":"CVE-2099-10001"}]},"extra_constraint":true}`)
	a := source.Advisory{ID: "USN-99999-1", Aliases: []string{cve, "CVE-2099-10002"}, Affected: []source.Affected{pkg, unscoped, wrongRelease, subscription, unsupported}}

	rows := 0
	err := Project(compactdb.All, "canonical-osv", a, func(group, key string, data []byte) error {
		rows++
		if group != "p" || key != compactdb.PackageKey(compactdb.UbuntuUSN, compactdb.PackageKey(jammy, pkg.Name)) {
			t.Fatalf("unexpected notice key %q/%q", group, key)
		}
		var row compactdb.Row
		if err := json.Unmarshal(data, &row); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(row.Aliases, []string{cve}) {
			t.Fatalf("unexpected notice CVEs: %v", row.Aliases)
		}
		return nil
	})
	if err != nil || rows != 1 {
		t.Fatalf("rows=%d, err=%v", rows, err)
	}
}
