// Package vuln provides advisory range DTOs. Legacy JSON feed DTOs are retained
// for schema reference; current applications distribute indexed disk snapshots.
package vuln

import (
	"encoding/json"
	"fmt"
	"time"
)

const FormatVersion = 3

// SyncFailed is the only error text stored in a feed. Raw upstream errors stay
// on the vulnfeed host because they can contain request details.
const SyncFailed = "sync failed"

// Feed is the obsolete JSON contract, not used by the current command path.
type Feed struct {
	FormatVersion int              `json:"format_version"`
	GeneratedAt   time.Time        `json:"generated_at"`
	Sources       []SourceRevision `json:"sources"`
	Records       []Record         `json:"records"`
	News          []NewsItem       `json:"news"`
}

type SourceRevision struct {
	ID            string    `json:"id"`
	FetchedAt     time.Time `json:"fetched_at"`
	LastAttemptAt time.Time `json:"last_attempt_at"`
	Cursor        string    `json:"cursor,omitempty"`
	// AdvisoryCount is how many advisories from this sync became records
	// before records that share an id were merged.
	AdvisoryCount int    `json:"advisory_count"`
	Error         string `json:"error,omitempty"`
}

type Record struct {
	ID             string     `json:"id"`
	Aliases        []string   `json:"aliases,omitempty"`
	Sources        []string   `json:"sources,omitempty"`
	Summary        string     `json:"summary,omitempty"`
	Severity       string     `json:"severity,omitempty"`
	Published      *time.Time `json:"published,omitempty"`
	Modified       time.Time  `json:"modified,omitempty"`
	Withdrawn      bool       `json:"withdrawn,omitempty"`
	Affected       []Product  `json:"affected,omitempty"`
	References     []string   `json:"references,omitempty"`
	Evidence       []Evidence `json:"evidence"`
	KnownExploited bool       `json:"known_exploited,omitempty"`
}

type Product struct {
	Ecosystem         string          `json:"ecosystem"`
	Name              string          `json:"name"`
	Ranges            []Range         `json:"ranges,omitempty"`
	Versions          []string        `json:"versions,omitempty"`
	EcosystemSpecific json.RawMessage `json:"ecosystem_specific,omitempty"`
	DatabaseSpecific  json.RawMessage `json:"database_specific,omitempty"`
}

type RangeEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}
type Range struct {
	DatabaseSpecific json.RawMessage `json:"database_specific,omitempty"`
	Type             string          `json:"type,omitempty"`
	Repo             string          `json:"repo,omitempty"`
	Events           []RangeEvent    `json:"events,omitempty"`
	Introduced       string          `json:"introduced,omitempty"`
	Fixed            string          `json:"fixed,omitempty"`
	LastAffected     string          `json:"last_affected,omitempty"`
}

func NewFeed(now time.Time) Feed {
	return Feed{
		FormatVersion: FormatVersion,
		GeneratedAt:   now.UTC(),
		Sources:       []SourceRevision{},
		Records:       []Record{},
		News:          []NewsItem{},
	}
}

func (f Feed) Validate() error {
	if f.FormatVersion != FormatVersion {
		return fmt.Errorf("vuln: format version %d, want %d", f.FormatVersion, FormatVersion)
	}
	if f.GeneratedAt.IsZero() {
		return fmt.Errorf("vuln: generated_at is required")
	}
	if f.Sources == nil || f.Records == nil || f.News == nil {
		return fmt.Errorf("vuln: sources, records and news must be present")
	}
	seen := map[string]bool{}
	for _, r := range f.Records {
		if r.ID == "" || seen[r.ID] || len(r.Evidence) == 0 {
			return fmt.Errorf("vuln: records require unique IDs and source evidence")
		}
		seen[r.ID] = true
		for _, e := range r.Evidence {
			if e.Source == "" || e.AdvisoryID == "" {
				return fmt.Errorf("vuln: evidence requires source and advisory identity")
			}
		}
	}
	return nil
}

// Evidence preserves source-specific facts. A source withdrawal is not a global CVE withdrawal.
type Evidence struct {
	UnmappedAffected int             `json:"unmapped_affected,omitempty"`
	Source           string          `json:"source"`
	AdvisoryID       string          `json:"advisory_id"`
	Severity         string          `json:"severity,omitempty"`
	Withdrawn        bool            `json:"withdrawn"`
	Modified         time.Time       `json:"modified"`
	Raw              json.RawMessage `json:"raw,omitempty"`
}
type NewsItem struct {
	ID              string    `json:"id"`
	VulnerabilityID string    `json:"vulnerability_id"`
	Reason          string    `json:"reason"`
	Source          string    `json:"source"`
	PublishedAt     time.Time `json:"published_at"`
	Summary         string    `json:"summary"`
	References      []string  `json:"references,omitempty"`
}
