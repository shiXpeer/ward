package collect

import "testing"

func TestDockerDPKGInstalledSourceVersion(t *testing.T) {
	got, err := parseDockerDPKG("Package: libexample\nStatus: install ok installed\nVersion: 2.1-3+b1\nSource: example (2.1-3)\nArchitecture: amd64\n\nPackage: removed\nStatus: deinstall ok config-files\nVersion: 1")
	if err != nil || len(got) != 1 {
		t.Fatalf("packages=%v error=%v", got, err)
	}
	if p := got[0]; p.Name != "libexample" || p.Version != "2.1-3+b1" || p.SourceName != "example" || p.SourceVersion != "2.1-3" {
		t.Fatalf("unexpected package: %+v", p)
	}
	if _, err := parseDockerDPKG("Package: broken\nStatus: install ok installed"); err == nil {
		t.Fatal("accepted an installed package without a version")
	}
}
