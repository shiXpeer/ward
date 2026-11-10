package scan

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"shixpeer.com/ward/internal/agent/database"
	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/pkg/inventory"
)

func vexProduct(eco string, release map[string]string, sourceName, sourceVersion string) (string, string) {
	if !strings.HasPrefix(eco, "Ubuntu:") {
		return "", ""
	}
	distro := inventory.UbuntuCodename(release)
	for _, field := range []struct{ name, value string }{
		{"source package name", sourceName}, {"source package version", sourceVersion}, {"VERSION_CODENAME", distro},
	} {
		if field.value == "" {
			return "", "Ubuntu VEX identity missing field: " + field.name
		}
		if compactdb.VEXProduct("placeholder", "1", field.value) == "" {
			return "", "Ubuntu VEX identity has invalid field: " + field.name
		}
	}
	return compactdb.VEXProduct(sourceName, sourceVersion, distro), ""
}

const maxPackageRules = 100000

// Collect only ambiguous OSV IDs before walking the VEX blocks. The normal
// scan still evaluates OSV independently, including when this pass fails.
func matchVEX(ctx context.Context, db *database.Reader, product, packageKey, version string) (map[string]string, error) {
	statements := map[string]string{}
	err := db.Lookup(ctx, "p", packageKey, maxPackageRules, func(raw []byte) error {
		var row compactdb.Row
		if err := json.Unmarshal(raw, &row); err != nil {
			return err
		}
		if row.Source != "canonical-osv" || !strings.HasPrefix(row.ID, "UBUNTU-CVE-") {
			return nil
		}
		d, err := evaluateIndexed(ctx, db, row, version)
		if err != nil {
			return err
		}
		if d.reason == ubuntuNoBoundary {
			statements[strings.TrimPrefix(row.ID, "UBUNTU-")] = ""
		}
		return nil
	})
	if err != nil || len(statements) == 0 {
		return nil, err
	}
	err = db.Walk(ctx, "p", compactdb.PackageKey(compactdb.UbuntuVEX, product), func(raw []byte) error {
		var row compactdb.Row
		var statement struct{ Status string }
		if json.Unmarshal(raw, &row) != nil || row.Ecosystem != compactdb.UbuntuVEX || row.Package != product ||
			!strings.HasPrefix(row.ID, "UBUNTU-VEX-CVE-") || json.Unmarshal(row.Context, &statement) != nil {
			return errors.New("invalid Ubuntu VEX index row")
		}
		id := strings.TrimPrefix(row.ID, "UBUNTU-VEX-")
		old, needed := statements[id]
		if !needed {
			return nil
		}
		if old != "" && old != statement.Status {
			statements[id] = "conflict"
		} else {
			statements[id] = statement.Status
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return statements, nil
}

func resolveVEX(status string) decision {
	switch status {
	case "affected_fix_deferred":
		return decision{state: "affected", reason: "Canonical VEX confirms this installed version is affected and remediation is deferred"}
	case "affected":
		return decision{state: "affected", reason: "Canonical VEX confirms this installed version is affected; no fixed version is available in the matched data"}
	case "fixed", "not_affected":
		return decision{state: "excluded"}
	}
	return decision{}
}

func ubuntuReviewReason(hasVEX bool, identityIssue string, lookupFailed bool, status string) string {
	switch {
	case !hasVEX:
		return "Ubuntu VEX is absent from the published database"
	case identityIssue != "":
		return identityIssue
	case lookupFailed:
		return "Ubuntu VEX lookup failed for this package"
	}
	switch status {
	case "under_investigation":
		return "Canonical VEX lists this version as under investigation"
	case "conflict":
		return "Canonical VEX statements disagree for this version"
	default:
		return "No Canonical VEX statement for this exact package version and Ubuntu release"
	}
}
