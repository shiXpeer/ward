package scan

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"

	"shixpeer.com/ward/internal/agent/database"
	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/internal/debversion"
	"shixpeer.com/ward/pkg/inventory"
)

func matchingJammyKernelOVAL(ctx context.Context, db *database.Reader, source, release string) (map[string]bool, error) {
	matches := map[string]bool{}
	patterns := map[string]bool{}
	err := db.Lookup(ctx, "p", compactdb.PackageKey(compactdb.UbuntuJammyOVAL, source), maxPackageRules, func(raw []byte) error {
		var row compactdb.Row
		var rule struct{ Pattern string }
		if json.Unmarshal(raw, &row) != nil || row.Ecosystem != compactdb.UbuntuJammyOVAL || row.Package != source ||
			json.Unmarshal(row.Context, &rule) != nil || rule.Pattern == "" || len(rule.Pattern) > 512 {
			return errors.New("invalid Ubuntu OVAL kernel row")
		}
		match, ok := patterns[rule.Pattern]
		if !ok {
			rx, err := regexp.Compile("^(?:" + rule.Pattern + ")$")
			if err != nil {
				return err
			}
			match = rx.MatchString(release)
			patterns[rule.Pattern] = match
		}
		if match {
			matches[row.ID] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return matches, nil
}

// A supported OVAL branch identifies a binary package and compares its actual
// dpkg version. Source versions are used only for associating the OSV finding.
func matchingJammyPackageOVAL(ctx context.Context, db *database.Reader, binaries []inventory.Package) (map[string]bool, error) {
	matches := map[string]bool{}
	for _, pkg := range binaries {
		err := db.Lookup(ctx, "p", compactdb.PackageKey(compactdb.UbuntuJammyPackageOVAL, pkg.Name), maxPackageRules, func(raw []byte) error {
			var row compactdb.Row
			var rule struct{ Fixed string }
			if json.Unmarshal(raw, &row) != nil || row.Ecosystem != compactdb.UbuntuJammyPackageOVAL ||
				row.Package != pkg.Name || json.Unmarshal(row.Context, &rule) != nil || rule.Fixed == "" {
				return errors.New("invalid Ubuntu OVAL package row")
			}
			cmp, err := debversion.Compare(pkg.Version, rule.Fixed)
			if err != nil {
				return err
			}
			if cmp < 0 {
				matches[row.ID] = true
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return matches, nil
}
