package projection

import (
	"encoding/json"
	"slices"

	"shixpeer.com/ward/internal/beacon/source"
	"shixpeer.com/ward/internal/evidence"
)

func usnPackageCVEs(a source.Advisory, p source.Affected) []string {
	var meta struct {
		Availability string
		Module       json.RawMessage `json:"module_name_regex"`
	}
	if len(p.EcosystemSpecific) > 0 {
		raw, err := evidence.Unpack(p.EcosystemSpecific)
		if err != nil || json.Unmarshal(raw, &meta) != nil {
			return nil
		}
	}
	if len(meta.Module) > 0 || (meta.Availability != "" && meta.Availability != "No subscription required") {
		return nil
	}
	var fields map[string]json.RawMessage
	if len(p.DatabaseSpecific) > 0 {
		raw, err := evidence.Unpack(p.DatabaseSpecific)
		if err != nil || json.Unmarshal(raw, &fields) != nil {
			return nil
		}
	}
	if len(fields) == 0 && len(a.Affected) == 1 {
		// Older single-package notices may only have notice-level CVE IDs.
		return a.Aliases
	}
	if len(fields) != 1 || fields["cves_map"] == nil {
		return nil
	}
	var mapping struct {
		Ecosystem string
		CVEs      []struct{ ID string }
	}
	if json.Unmarshal(fields["cves_map"], &mapping) != nil || mapping.Ecosystem != p.Ecosystem {
		return nil
	}
	var ids []string
	for _, cve := range mapping.CVEs {
		if slices.Contains(a.Aliases, cve.ID) {
			ids = append(ids, cve.ID)
		}
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}
