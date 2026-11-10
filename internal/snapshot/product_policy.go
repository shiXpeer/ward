package snapshot

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const MaxProductPolicy = 256 << 10

type ProductPolicy struct {
	Version    int                `json:"version"`
	Formula    map[string]string  `json:"formula"`
	Bundle     map[string]string  `json:"bundle"`
	Exclusions []ProductExclusion `json:"exclusions,omitempty"`
}

type ProductExclusion struct {
	Product       string            `json:"product"`
	CVEs          []string          `json:"cves"`
	Formula       string            `json:"formula,omitempty"`
	Installed     string            `json:"installed,omitempty"`
	Upstream      string            `json:"upstream,omitempty"`
	Platforms     []string          `json:"platforms,omitempty"`
	Bottle        string            `json:"bottle,omitempty"`
	FixedByBranch map[string]string `json:"fixed_by_branch,omitempty"`
}

var productKey = regexp.MustCompile(`^a:[a-z0-9_.-]+:[a-z0-9_.-]+$`)
var inventoryKey = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.+@-]{0,255}$`)
var cveKey = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
var branchKey = regexp.MustCompile(`^[0-9]{1,9}\.[0-9]{1,9}$`)
var releaseKey = regexp.MustCompile(`^[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}$`)

func (p *ProductPolicy) Validate() error {
	if p == nil {
		return nil
	}
	raw, err := json.Marshal(p)
	if err != nil || len(raw) > MaxProductPolicy || p.Version != 1 {
		return fmt.Errorf("unsupported or oversized product policy")
	}
	products := map[string]bool{}
	for _, table := range []map[string]string{p.Formula, p.Bundle} {
		for key, product := range table {
			if !inventoryKey.MatchString(key) || !productKey.MatchString(product) {
				return fmt.Errorf("invalid product binding %q", key)
			}
			products[product] = true
		}
	}
	for _, rule := range p.Exclusions {
		if !products[rule.Product] || len(rule.CVEs) == 0 ||
			(rule.Formula == "" && (rule.Installed != "" || rule.Bottle != "")) ||
			(rule.Formula != "" && (p.Formula[rule.Formula] != rule.Product || rule.Installed == "" || rule.Upstream == "")) ||
			(rule.Upstream == "" && len(rule.Platforms) == 0 && len(rule.FixedByBranch) == 0) {
			return fmt.Errorf("invalid exclusion for %q", rule.Product)
		}
		for _, field := range []string{rule.Installed, rule.Upstream, rule.Bottle} {
			if field != "" && !inventoryKey.MatchString(field) {
				return fmt.Errorf("invalid exclusion constraint %q", field)
			}
		}
		for _, platform := range rule.Platforms {
			if platform != "darwin" && platform != "linux" && platform != "windows" {
				return fmt.Errorf("invalid exclusion platform %q", platform)
			}
		}
		for _, id := range rule.CVEs {
			if !cveKey.MatchString(id) {
				return fmt.Errorf("invalid exclusion CVE %q", id)
			}
		}
		for branch, fixed := range rule.FixedByBranch {
			if !branchKey.MatchString(branch) || !releaseKey.MatchString(fixed) || !strings.HasPrefix(fixed, branch+".") {
				return fmt.Errorf("invalid fixed release %q for branch %q", fixed, branch)
			}
		}
	}
	return nil
}
