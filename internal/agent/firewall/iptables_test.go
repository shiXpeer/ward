package firewall

import (
	"net/netip"
	"testing"
)

func TestOriginalPortAndSourceAfterDNAT(t *testing.T) {
	tables, err := Parse(`*nat
:PREROUTING ACCEPT [0:0]
-A PREROUTING -p tcp --dport 9090 -j DNAT --to-destination 172.19.0.2:8080
COMMIT
*filter
:FORWARD DROP [0:0]
:DOCKER-USER - [0:0]
-A FORWARD -j DOCKER-USER
-A FORWARD -d 172.19.0.2/32 -p tcp --dport 8080 -j ACCEPT
-A DOCKER-USER -p tcp -m conntrack --ctorigdstport 9090 ! -s 198.51.100.171/32 -j DROP
COMMIT
`)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ source, status string }{
		{"198.51.100.170", "BLOCKED"},
		{"198.51.100.171", "ALLOWED"},
		{"198.51.100.172", "BLOCKED"},
	} {
		r := tables.Evaluate(Packet{
			Source: netip.MustParseAddr(c.source), Destination: netip.MustParseAddr("192.0.2.1"),
			Protocol: "tcp", Port: 9090, In: "eth0", Local: true,
			Output: func(netip.Addr) string { return "docker0" },
		}, true)
		if r.Status != c.status {
			t.Fatalf("%s: %+v", c.source, r)
		}
	}
	if boundaries := tables.SourceBoundaries(false); len(boundaries) != 3 || boundaries[1].String() != "198.51.100.171" || boundaries[2].String() != "198.51.100.172" {
		t.Fatalf("unexpected source partition: %v", boundaries)
	}
}

func TestUnsupportedMatchDoesNotAllow(t *testing.T) {
	tables, err := Parse(`*filter
:INPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 22 -m set --match-set deny src -j DROP
COMMIT
`)
	if err != nil {
		t.Fatal(err)
	}
	p := Packet{Source: netip.MustParseAddr("192.0.2.2"), Destination: netip.MustParseAddr("192.0.2.1"), Protocol: "tcp", Port: 22, In: "eth0", Local: true}
	if r := tables.Evaluate(p, false); r.Status != "UNKNOWN" {
		t.Fatalf("unsupported matching path: %+v", r)
	}
	p.Port = 80
	if r := tables.Evaluate(p, false); r.Status != "ALLOWED" {
		t.Fatalf("unrelated port: %+v", r)
	}
}
