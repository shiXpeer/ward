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
func TestLaunchedApplicationsOutsideStandardFolders(t *testing.T) {
	home := t.TempDir()
	opened := filepath.Join(t.TempDir(), "Dock Expose.app")
	helper := filepath.Join(t.TempDir(), "Library", "Helper.app")
	unopened := filepath.Join(t.TempDir(), "Quiet.app")
	nested := filepath.Join(t.TempDir(), "Outer.app", "Contents", "Inner.app")
	built := filepath.Join(t.TempDir(), "node_modules", "Tool.app")
	for _, path := range []string{opened, helper, unopened, nested, built} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	prefs := filepath.Join(home, "Library", "Preferences")
	if err := os.MkdirAll(prefs, 0700); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"com.example.opened", "com.example.helper"} {
		if err := os.WriteFile(filepath.Join(prefs, id+".plist"), []byte("bplist"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	h := Host{Command: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		switch name {
		case "mdfind":
			if len(args) != 1 || args[0] != "kMDItemContentTypeTree == 'com.apple.application-bundle'" {
				t.Fatalf("mdfind args %v", args)
			}
			return []byte(strings.Join([]string{
				opened + "/Contents/MacOS/Dock",
				helper,
				unopened,
				nested,
				built,
				"/Applications/Already.app",
				"relative.app",
			}, "\n")), nil
		case "plutil":
			plist := args[len(args)-1]
			switch {
			case strings.Contains(plist, "Dock Expose.app"):
				return []byte(`{"CFBundleName":"Dock Exposé","CFBundleIdentifier":"com.example.opened","CFBundleShortVersionString":"4.00.8"}`), nil
			case strings.Contains(plist, "Helper.app"):
				return []byte(`{"CFBundleName":"Helper","CFBundleIdentifier":"com.example.helper","CFBundleShortVersionString":"1"}`), nil
			case strings.Contains(plist, "Quiet.app"):
				return []byte(`{"CFBundleName":"Quiet","CFBundleIdentifier":"com.example.quiet","CFBundleShortVersionString":"1"}`), nil
			default:
				return nil, errors.New("unreadable plist")
			}
		default:
			t.Fatalf("unexpected command %s", name)
			return nil, errors.New("unexpected")
		}
	}}
	s := inventory.Snapshot{
		Applications: []inventory.Application{{Name: "Already", Identifier: "com.example.already", Version: "1"}},
		Coverage:     []inventory.Note{},
	}
	h.launchedApplications(context.Background(), &s, home)
	if len(s.Applications) != 2 || s.Applications[1].Identifier != "com.example.opened" || s.Applications[1].Version != "4.00.8" {
		t.Fatal(s.Applications)
	}
	if len(s.Coverage) != 0 {
		t.Fatal(s.Coverage)
	}
}

func TestLaunchedApplicationsReportsSpotlightFailure(t *testing.T) {
	s := inventory.Snapshot{
		Applications: []inventory.Application{{Name: "Kept", Identifier: "com.example.kept", Version: "1"}},
		Coverage:     []inventory.Note{},
	}
	h := Host{Command: func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name != "mdfind" {
			t.Fatal(name)
		}
		return nil, errors.New("spotlight unavailable")
	}}
	h.launchedApplications(context.Background(), &s, t.TempDir())
	if len(s.Applications) != 1 || len(s.Coverage) != 1 || s.Coverage[0].Code != inventory.Unavailable {
		t.Fatal(s.Applications, s.Coverage)
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
