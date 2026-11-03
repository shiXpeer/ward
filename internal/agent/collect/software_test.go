package collect

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"shixpeer.com/ward/pkg/inventory"
)

func TestDPKGSourceVersionAndStatus(t *testing.T) {
	text := "installed\tlibssl3:amd64\t3.0.14-1~deb12u2\tamd64\topenssl\t3.0.14-1~deb12u2\n" +
		"config-files\told\t1.0\tall\told\t1.0\n" +
		"installed\tfoo\t2:1.0-1\tall\t\t\n"
	p, e := parseDPKG(text)
	if e != nil || len(p) != 2 {
		t.Fatal(p, e)
	}
	if p[0].Name != "libssl3" || p[0].SourceName != "openssl" || p[0].SourceVersion != "3.0.14-1~deb12u2" {
		t.Fatal(p)
	}
	if p[1].SourceName != "foo" || p[1].SourceVersion != "2:1.0-1" {
		t.Fatal(p[1])
	}
	if _, e = parseDPKG("installed\tbroken\n"); e == nil {
		t.Fatal("bad output accepted")
	}
}
func TestBrewReadOnlyArgumentsAndAllInstalledVersions(t *testing.T) {
	s := inventory.Snapshot{Coverage: []inventory.Note{}}
	h := Host{Command: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "brew" && len(args) == 1 && args[0] == "--cellar" {
			return nil, errors.New("no receipt fixture")
		}
		if name != "brew" || strings.Join(args, " ") != "list --versions --formula" && strings.Join(args, " ") != "list --versions --cask" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		if args[2] == "--cask" {
			return nil, errors.New("missing")
		}
		return []byte("openssl@3 3.5.1 3.5.2\nxz 5.8.0\n"), nil
	}}
	h.brew(context.Background(), &s)
	if len(s.Packages) != 3 || len(s.Coverage) != 1 {
		t.Fatal(s)
	}
}
func TestBundleEnumerationDoesNotExecuteAppsOrFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"Safe.app/Contents", "Utilities/Other.app/Contents", "Too/Deep/Hidden.app/Contents"} {
		if err := os.MkdirAll(filepath.Join(root, p), 0700); err != nil {
			t.Fatal(err)
		}
	}
	external := filepath.Join(t.TempDir(), "External.app")
	os.Mkdir(external, 0700)
	os.Symlink(external, filepath.Join(root, "Linked.app"))
	var calls []string
	h := Host{Command: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name != "plutil" || len(args) != 5 || strings.Join(args[:4], " ") != "-convert json -o -" {
			t.Fatalf("unexpected probe %s %v", name, args)
		}
		calls = append(calls, args[len(args)-1])
		return []byte(`{"CFBundleName":"Synthetic App","CFBundleIdentifier":"test.local.app","CFBundleShortVersionString":"1.2.3"}`), nil
	}}
	s := inventory.Snapshot{Coverage: []inventory.Note{}}
	h.applicationDirs(context.Background(), &s, []string{root})
	if len(calls) != 2 || len(s.Applications) != 2 {
		t.Fatal(calls, s)
	}
	if s.Applications[0].Identifier != "test.local.app" {
		t.Fatal(s.Applications)
	}
	for _, c := range calls {
		if strings.Contains(c, "Hidden") || strings.Contains(c, "Linked") {
			t.Fatal(c)
		}
	}
}
func TestOutputLimit(t *testing.T) {
	b := limitedOutput{limit: 4}
	if _, e := b.Write([]byte("1234")); e != nil {
		t.Fatal(e)
	}
	if _, e := b.Write([]byte("5")); e == nil {
		t.Fatal("limit ignored")
	}
	if string(b.data) != "1234" {
		t.Fatal("partial overflow retained")
	}
}
