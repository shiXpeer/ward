package scan

import (
	"slices"
	"strings"

	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/internal/snapshot"
)

func correctedNVDMatch(policy *snapshot.ProductPolicy, row compactdb.Row, origin, name, installed, upstream, platform, bottle string) bool {
	if policy == nil || row.Source != "nvd" {
		return false
	}
	for _, rule := range policy.Exclusions {
		if rule.Product != row.Package || !slices.Contains(rule.CVEs, row.ID) ||
			(len(rule.Platforms) != 0 && !slices.Contains(rule.Platforms, platform)) ||
			(rule.Formula != "" && (origin != "homebrew-formula" || rule.Formula != name || rule.Installed != installed)) ||
			(rule.Upstream != "" && rule.Upstream != upstream) ||
			(rule.Bottle != "" && rule.Bottle != bottle) {
			continue
		}
		if len(rule.FixedByBranch) == 0 {
			return true
		}
		parts := strings.Split(upstream, ".")
		if len(parts) != 3 {
			continue
		}
		if fixed := rule.FixedByBranch[parts[0]+"."+parts[1]]; fixed != "" {
			if order, err := decimalVersion(upstream, fixed); err == nil && order >= 0 {
				return true
			}
		}
	}
	return false
}
