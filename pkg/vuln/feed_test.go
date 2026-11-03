package vuln

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNewFeedRoundTrip(t *testing.T) {
	feed := NewFeed(time.Date(2026, 10, 30, 8, 0, 0, 0, time.FixedZone("CEST", 2*60*60)))
	if err := feed.Validate(); err != nil {
		t.Fatal(err)
	}
	if feed.GeneratedAt.Location() != time.UTC {
		t.Fatal("generated_at was not stored in UTC")
	}
	raw, err := json.Marshal(feed)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Feed
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Records) != 0 || len(decoded.Sources) != 0 {
		t.Fatalf("decoded %#v", decoded)
	}
}

func TestFeedValidateRejectsMissingArrays(t *testing.T) {
	feed := Feed{FormatVersion: FormatVersion, GeneratedAt: time.Now().UTC()}
	if err := feed.Validate(); err == nil {
		t.Fatal("expected missing arrays")
	}
}
