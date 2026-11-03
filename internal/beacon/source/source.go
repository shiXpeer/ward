// Package source is the allowlist boundary. A source is chosen by the
// vulnfeed process. Nothing in this package discovers URLs on its own.
package source

import (
	"context"
	"encoding/json"
	"shixpeer.com/ward/pkg/vuln"
	"time"
)

type Source interface {
	ID() string
	Sync(ctx context.Context, cursor string) (Batch, error)
}

// Batch is the pre-normalization result of one verified source.
type Batch struct {
	// Full replaces a source snapshot; otherwise this is a delta keyed by advisory ID.
	Full       bool `json:"full"`
	Cursor     string
	FetchedAt  time.Time
	Advisories []Advisory
}

type Advisory struct {
	UnmappedAffected int
	Raw              json.RawMessage
	KnownExploited   bool
	ExploitedAt      time.Time
	ID               string
	Aliases          []string
	Summary          string
	Severity         string
	Published        time.Time
	Modified         time.Time
	Withdrawn        bool
	References       []string
	Affected         []Affected
}

type Affected struct {
	Ranges            []vuln.Range
	Versions          []string
	EcosystemSpecific json.RawMessage
	DatabaseSpecific  json.RawMessage
	Ecosystem         string
	Name              string
	Introduced        string
	Fixed             string
	LastAffected      string
}
