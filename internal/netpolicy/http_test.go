package netpolicy

import "testing"

func TestOnlyExplicitHTTPSHosts(t *testing.T) {
	for _, raw := range []string{"http://good.example/feed", "https://evil.example/feed", "https://user:secret@good.example/feed", "https://good.example/feed#fragment", "file:///tmp/feed"} {
		if e := URL(raw, []string{"good.example"}); e == nil {
			t.Fatal("accepted", raw)
		}
	}
	if e := URL("https://good.example:8443/v1/manifest.json", []string{"good.example"}); e != nil {
		t.Fatal(e)
	}
}
