// Package productid loads publisher-side product policy.
package productid

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"

	"shixpeer.com/ward/internal/atomicfile"
	"shixpeer.com/ward/internal/cpe"
	"shixpeer.com/ward/internal/snapshot"
)

const DockerDesktop = cpe.DockerDesktop
const DockerDesktopRuleFormat = cpe.DockerDesktopRuleFormat

const ExpandedMacRuleFormat = "nvd-cpe-macos-products-v1"

const ExtendedHomebrewRuleFormat = "nvd-cpe-homebrew-products-v1"

const AdditionalProductRuleFormat = "nvd-cpe-additional-products-v1"

const DesktopAndLibrariesRuleFormat = "nvd-cpe-desktop-libraries-v1"

//go:embed defaults.json
var defaults []byte

var Policy = func() *snapshot.ProductPolicy {
	var p snapshot.ProductPolicy
	if err := json.Unmarshal(defaults, &p); err != nil {
		panic(err)
	}
	if err := p.Validate(); err != nil {
		panic(err)
	}
	return &p
}()

// Load replaces the default policy at publisher startup, before any workers run.
func Load(path string) error {
	var raw json.RawMessage
	if err := atomicfile.ReadJSON(path, &raw, snapshot.MaxProductPolicy); err != nil {
		return err
	}
	var p snapshot.ProductPolicy
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil {
		return fmt.Errorf("product policy: %w", err)
	}
	if err := p.Validate(); err != nil {
		return err
	}
	Policy = &p
	known = index(&p)
	return nil
}

func Known(key string) bool {
	return known[key]
}

var known = index(Policy)

func index(p *snapshot.ProductPolicy) map[string]bool {
	m := map[string]bool{}
	for _, table := range []map[string]string{p.Formula, p.Bundle} {
		for _, product := range table {
			m[product] = true
		}
	}
	return m
}
