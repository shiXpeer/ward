// Package compactdb is a file format and disk index, not a database engine.
// Queries use ReadAt binary search; no complete database/index is loaded into RAM.
package compactdb

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"shixpeer.com/ward/pkg/vuln"
	"sort"
	"time"
)

const Format = 3

const MaxValue = 8 << 20
const MaxRow = 64 << 10
const SortBudget = 8 << 20
const GroupCount = 4

var Groups = []string{"p", "v", "r", "s"}

type Row struct {
	Source         string          `json:"source"`
	ID             string          `json:"id"`
	Aliases        []string        `json:"aliases,omitempty"`
	Ecosystem      string          `json:"ecosystem,omitempty"`
	Package        string          `json:"package,omitempty"`
	Severity       string          `json:"severity,omitempty"`
	Withdrawn      bool            `json:"withdrawn,omitempty"`
	Ranges         []vuln.Range    `json:"ranges,omitempty"`
	Versions       []string        `json:"versions,omitempty"`
	VersionSet     string          `json:"version_set,omitempty"`
	Context        json.RawMessage `json:"context,omitempty"`
	Status         string          `json:"status,omitempty"`
	Review         bool            `json:"requires_review,omitempty"`
	SourcePackage  bool            `json:"source_package,omitempty"`
	Unmapped       int             `json:"unmapped_affected,omitempty"`
	References     []string        `json:"references,omitempty"`
	Modified       string          `json:"modified,omitempty"`
	KnownExploited bool            `json:"known_exploited,omitempty"`
	Probability    *float64        `json:"epss,omitempty"`
	Percentile     *float64        `json:"percentile,omitempty"`
}
type Profile string

const All Profile = "all"
const Prototype Profile = "prototype"

func (p Profile) Validate() error {
	if p != All && p != Prototype {
		return fmt.Errorf("unknown publication profile %q", p)
	}
	return nil
}
func (p Profile) Accept(eco string) bool {
	return p == All || eco == "Ubuntu:24.04:LTS" || eco == "Debian:bookworm" || eco == "Debian:12" || eco == "macOS"
}
func PackageKey(eco, pkg string) string  { return eco + "\x00" + pkg }
func KeyHash(group, key string) [32]byte { return sha256.Sum256([]byte(group + "\x00" + key)) }
func Slot(group, key string) string {
	h := KeyHash(group, key)
	return fmt.Sprintf("%s-%02x", group, slotByte(group, h[0]))
}
func Digest(b []byte) string { x := sha256.Sum256(b); return hex.EncodeToString(x[:]) }

type Put func(group, key string, value []byte) error

func sortedUnique(v []string) []string {
	v = append([]string(nil), v...)
	sort.Strings(v)
	out := v[:0]
	for _, s := range v {
		if len(out) == 0 || out[len(out)-1] != s {
			out = append(out, s)
		}
	}
	return out
}

func slotByte(group string, b byte) byte {
	if group == "s" {
		return b & 0x7f
	}
	return b
}

type SourceStatus struct {
	RuleFormats []string  `json:"rule_formats,omitempty"`
	Revision    string    `json:"input_revision"`
	ID          string    `json:"id"`
	Advisories  int64     `json:"advisories"`
	Inputs      int       `json:"inputs"`
	Cached      int       `json:"cached"`
	CheckedAt   time.Time `json:"checked_at"`
}
