package scan

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"shixpeer.com/ward/internal/agent/database"
	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/internal/debversion"
)

type usnFix struct{ version, notice string }

// USNs supply remediation versions for already applicable findings. A
// bulletin's lower bound does not by itself establish installed applicability.
func ubuntuUSNFixes(ctx context.Context, db *database.Reader, ecosystem, pkg, version string) (map[string]usnFix, error) {
	fixes := map[string]usnFix{}
	key := compactdb.PackageKey(compactdb.UbuntuUSN, compactdb.PackageKey(ecosystem, pkg))
	err := db.Walk(ctx, "p", key, func(raw []byte) error {
		var row compactdb.Row
		if json.Unmarshal(raw, &row) != nil || row.Ecosystem != ecosystem || row.Package != pkg || row.Source != "canonical-osv" || !strings.HasPrefix(row.ID, "USN-") {
			return errors.New("invalid Canonical USN index row")
		}
		for _, rule := range row.Ranges {
			match, versions, err := inRange(version, rule, debversion.Compare)
			if err != nil || !match {
				continue
			}
			for _, fix := range versions {
				for _, cve := range row.Aliases {
					if !strings.HasPrefix(cve, "CVE-") {
						continue
					}
					old := fixes[cve]
					if old.version == "" {
						fixes[cve] = usnFix{fix, row.ID}
						continue
					}
					if cmp, err := debversion.Compare(fix, old.version); err == nil && cmp < 0 {
						fixes[cve] = usnFix{fix, row.ID}
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return fixes, nil
}
