// shixpeer-ward-agent observes a host and fetches signed vulnerability snapshots.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"shixpeer.com/ward/internal/agent/agent"
	"shixpeer.com/ward/internal/agent/collect"
	"shixpeer.com/ward/internal/agent/database"
	"shixpeer.com/ward/internal/agent/state"
	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/internal/identity"
	"shixpeer.com/ward/internal/netpolicy"
	"shixpeer.com/ward/internal/paths"
	"strings"
	"syscall"
	"time"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("shixpeer-ward-agent: ")
	if e := run(os.Args[1:]); e != nil && !errors.Is(e, context.Canceled) && !errors.Is(e, flag.ErrHelp) {
		log.Print(e)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		args = []string{"update"}
	}
	if args[0] == "migrate-home" {
		return migrateHome(args[1:])
	}
	if args[0] == "version" {
		fmt.Println(collect.Version)
		return nil
	}
	if args[0] == "help" || args[0] == "--help" {
		fmt.Println("Shixpeer Ward — https://shixpeer.com\nCommands: setup (save download settings), update (signed database, changed objects only; default), pull (alias), scan (offline system report), collect (offline), lookup (offline), run (resident update + scan), migrate-home (copy legacy state into home).\nUse COMMAND -h for options. No software updates or remote commands.")
		return nil
	}
	cmd := args[0]
	if cmd != "collect" && cmd != "pull" && cmd != "update" && cmd != "setup" && cmd != "run" && cmd != "lookup" && cmd != "scan" {
		return errors.New("unknown command")
	}
	if paths.Root() == "" {
		return errors.New("HOME must be an absolute directory")
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	configPath := fs.String("config", paths.Config("agent"), "saved agent settings file")
	dir := fs.String("state", paths.State("agent"), "private local state directory")
	raw := fs.String("feed-url", os.Getenv("SHIXPEER_WARD_AGENT_FEED_URL"), "signed manifest HTTPS URL")
	keyfile := fs.String("trusted-key", "", "trusted feed.pub, provisioned out of band")
	cafile := fs.String("ca-file", "", "private Beacon CA certificate; omit for public/GitHub HTTPS")
	allow := fs.String("allow-hosts", "", "additional HTTPS redirect/artifact hostnames, comma-separated")
	reportDir := fs.String("report-dir", "", "scan report directory; default state directory")
	group := fs.String("group", "p", "lookup: p (package), v (advisory), r (risk)")
	ecosystem := fs.String("ecosystem", "", "lookup package ecosystem, e.g. Debian:bookworm")
	pkg := fs.String("package", "", "lookup source package name")
	id := fs.String("id", "", "lookup advisory/CVE identifier")
	limit := fs.Int("limit", 100, "maximum local lookup rows, 1..10000")
	collectEvery := fs.Duration("collect-interval", 15*time.Minute, "scan/report interval")
	feedEvery := fs.Duration("feed-interval", 6*time.Hour, "snapshot interval")
	if e := fs.Parse(args[1:]); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}

	saved, e := loadSettings(*configPath)
	if e != nil {
		return e
	}
	explicit := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	if !explicit["state"] && saved.State != "" {
		*dir = saved.State
	}
	if !explicit["feed-url"] && *raw == "" {
		*raw = saved.URL
	}
	if !explicit["ca-file"] {
		*cafile = saved.CA
	}
	if !explicit["allow-hosts"] {
		*allow = strings.Join(saved.Hosts, ",")
	}
	pub := ed25519.PublicKey(saved.Key)
	if *keyfile != "" {
		pub, e = identity.Public(*keyfile)
		if e != nil {
			return e
		}
	}
	if cmd == "setup" {
		return saveSettings(*configPath, *dir, *raw, pub, *cafile, *allow)
	}
	st, e := state.Open(*dir)
	if e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cmd == "scan" {
		return runScan(ctx, *dir, *reportDir, pub, (collect.Host{}).SoftwareSnapshot)
	}
	if cmd == "collect" {
		snap, e := (collect.Host{}).Snapshot(ctx)
		if e != nil {
			return e
		}
		if e = snap.Validate(); e != nil {
			return e
		}
		if e = st.SaveSnapshot(ctx, snap); e != nil {
			return e
		}
		fmt.Println(filepath.Join(*dir, state.SnapshotFile))
		return nil
	}
	if cmd == "lookup" {
		key := *id
		if *group == "p" {
			if *ecosystem == "" || *pkg == "" {
				return errors.New("package lookup requires -ecosystem and -package")
			}
			key = compactdb.PackageKey(*ecosystem, *pkg)
		} else if (*group != "r" && *group != "v") || key == "" {
			return errors.New("lookup requires group p/r/v and a package or -id")
		}
		return database.Lookup(ctx, filepath.Join(*dir, "database"), *group, key, *limit, func(b []byte) error { _, e := fmt.Fprintln(os.Stdout, string(b)); return e })
	}
	var feeds *database.Client
	if *raw != "" {
		if len(pub) != ed25519.PublicKeySize {
			return errors.New("trusted publisher key missing: run setup -feed-url HTTPS_URL -trusted-key feed.pub once")
		}
		hosts := strings.FieldsFunc(*allow, func(r rune) bool { return r == ',' })
		httpc, e := netpolicy.Client(*cafile, hosts)
		if e != nil {
			return e
		}
		feeds = &database.Client{URL: *raw, HTTP: httpc, TrustedKey: pub, AllowedHosts: hosts, Dir: filepath.Join(*dir, "database")}
	}
	if cmd == "pull" || cmd == "update" {
		if feeds == nil {
			return errors.New("no download source configured: run setup -feed-url HTTPS_URL -trusted-key feed.pub once")
		}
		result, e := feeds.Update(ctx)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(result)
	}
	var update func(context.Context) error
	if feeds != nil {
		update = feeds.Refresh
	}
	logs, err := agent.OpenLog(filepath.Join(paths.Root(), "logs", "agent.log"), 4<<20)
	if err != nil {
		return err
	}
	defer logs.Close()
	logger := log.New(logs, "", log.LstdFlags)
	fmt.Println("Resident update + scan started; bounded logs:", filepath.Join(paths.Root(), "logs", "agent.log"))
	return agent.Resident(ctx, update, func(ctx context.Context) error {
		return runScanTo(ctx, *dir, *reportDir, pub, (collect.Host{}).SoftwareSnapshot, logs, logs)
	}, *feedEvery, *collectEvery, logger)
}
