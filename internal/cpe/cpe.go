// Package cpe retains NVD applicability evidence. Only simple OR alternatives
// are eligible for confirmation; AND, negation and target constraints survive
// as review evidence. Parsing is deliberately stricter than the full CPE grammar.
package cpe

import (
	"encoding/json"
	"errors"
	"strings"
)

const RuleFormat = "nvd-cpe-v1"
const DockerDesktop = "a:docker:docker_desktop"
const DockerDesktopRuleFormat = "nvd-cpe-docker-desktop-v1"

type Name struct{ Part, Vendor, Product, Version, Update, Edition, Language, SWEdition, TargetSW, TargetHW, Other string }

func Parse(s string) (Name, error) {
	// Escaped and wildcarded product names need the full CPE binding algorithm.
	if strings.Contains(s, "\\") {
		return Name{}, errors.New("escaped CPE unsupported")
	}
	f := strings.Split(s, ":")
	if len(f) != 13 || f[0] != "cpe" || f[1] != "2.3" || (f[2] != "a" && f[2] != "o") {
		return Name{}, errors.New("unsupported CPE")
	}
	for _, v := range f[3:5] {
		if v == "" || v == "-" || strings.ContainsAny(v, "*?") {
			return Name{}, errors.New("nonliteral CPE product")
		}
	}

	return Name{f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9], f[10], f[11], f[12]}, nil
}
func (n Name) Key() string { return n.Part + ":" + n.Vendor + ":" + n.Product }

type Match struct {
	Vulnerable     bool   `json:"vulnerable"`
	Criteria       string `json:"criteria"`
	StartIncluding string `json:"versionStartIncluding,omitempty"`
	StartExcluding string `json:"versionStartExcluding,omitempty"`
	EndIncluding   string `json:"versionEndIncluding,omitempty"`
	EndExcluding   string `json:"versionEndExcluding,omitempty"`
}
type Node struct {
	Operator string  `json:"operator"`
	Negate   bool    `json:"negate"`
	Matches  []Match `json:"cpeMatch"`
	Nodes    []Node  `json:"nodes"`
	Children []Node  `json:"children"`
}
type Rule struct {
	Match   Match `json:"match"`
	Complex bool  `json:"complex"`
	Negated bool  `json:"negated,omitempty"`
}

// Extract retains every positive vulnerable leaf, including leaves in complex
// trees. A complex leaf can only support review, never a standalone verdict.
func Extract(raw json.RawMessage) ([]Rule, error) {
	var roots []Node
	if err := json.Unmarshal(raw, &roots); err != nil {
		return nil, err
	}
	out := []Rule{}
	visited := 0
	var walk func(Node, bool, bool, int) error
	walk = func(n Node, complex, negated bool, depth int) error {
		negated = negated || n.Negate
		visited++
		if visited > 8192 || depth > 32 {
			return errors.New("CPE configuration limit exceeded")
		}
		terms := len(n.Matches) + len(n.Nodes) + len(n.Children)
		complex = complex || n.Negate || (n.Operator != "" && n.Operator != "OR") || (n.Operator == "" && terms > 1)
		for _, m := range n.Matches {
			if m.Vulnerable {
				out = append(out, Rule{Match: m, Complex: complex, Negated: negated})
				if len(out) > 8192 {
					return errors.New("CPE match limit exceeded")
				}
			}
		}
		for _, list := range [][]Node{n.Nodes, n.Children} {
			for _, child := range list {
				if err := walk(child, complex, negated, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	for _, n := range roots {
		if err := walk(n, false, false, 0); err != nil {
			return nil, err
		}
	}
	return out, nil
}
