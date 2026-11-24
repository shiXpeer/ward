// shixpeer-ward-beacon aggregates sources and publishes signed database snapshots.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"shixpeer.com/ward/internal/beacon/catalog"
	"shixpeer.com/ward/internal/beacon/exporter"
	"shixpeer.com/ward/internal/beacon/publish"
	"shixpeer.com/ward/internal/beacon/source"
	"shixpeer.com/ward/internal/buildinfo"
	"shixpeer.com/ward/internal/compactdb"
	"shixpeer.com/ward/internal/distribution"
	"shixpeer.com/ward/internal/filelock"
	"shixpeer.com/ward/internal/identity"
	"shixpeer.com/ward/internal/netpolicy"
	"shixpeer.com/ward/internal/paths"
	"shixpeer.com/ward/internal/productid"
	"shixpeer.com/ward/internal/updategateway"
	"strings"
	"sync"
	"syscall"
	"time"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("shixpeer-ward-beacon: ")
	if e := run(os.Args[1:]); e != nil && !errors.Is(e, context.Canceled) && !errors.Is(e, flag.ErrHelp) {
		log.Print(e)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: shixpeer-ward-beacon init|sync|export|serve|run|news|check-sources|status|version|help")
	}
	cmd := args[0]
	if cmd == "version" {
		fmt.Println(buildinfo.Version)
		return nil
	}
	if cmd == "help" || cmd == "--help" {
		fmt.Println("Shixpeer Ward Beacon — https://shixpeer.com\nrelease: publish signed Linux agents and installer\ninit: create private TLS identity and separate data-signing key\nsync: fetch configured sources and normalize locally\ncheck-sources: download and validate each source, compile streaming inputs, fail if any source fails\nstatus: show compact catalog coverage and size\nexport: write portable signed artifacts for Beacon or GitHub\nserve: expose only public artifacts over HTTPS\nrun: periodic sync/export plus HTTPS server\nUse COMMAND -h for options.")
		return nil
	}
	if paths.Root() == "" {
		return errors.New("HOME must be an absolute directory")
	}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	metadataSources := fs.String("update-sources", "", "operator-approved public update metadata sources JSON")
	metadataCache := fs.String("update-cache", "", "bounded Homebrew metadata disk cache (with update-sources)")
	binaries := fs.String("binaries", "", "release: directory containing Linux agents for amd64 and arm64")
	releaseTTL := fs.Duration("release-ttl", 7*24*time.Hour, "release: installer artifact validity, max 30d")
	dir := fs.String("state", paths.State("beacon"), "private state directory, no SQL required")
	defaultVEX := fs.Bool("with-default-ubuntu-vex", false, "add the default VEX companion to legacy Canonical OSV configurations")
	sourceWorkers := fs.Int("source-workers", catalog.DefaultSourceWorkers, "maximum concurrent source downloads (1–8)")
	retain := fs.Bool("keep-other-sources", false, "sync selected sources while retaining existing sources and their freshness")
	policy := fs.String("product-policy", "", "publisher JSON product policy override for sync or run")
	config := fs.String("sources", paths.Config("beacon"), "local JSON source configuration")
	pki := fs.String("pki", "", "new identity directory (init only)")
	hosts := fs.String("hosts", "localhost,127.0.0.1,::1", "TLS SAN hostnames/IPs (init only)")
	out := fs.String("out", "", "public artifact directory; default STATE/public")
	signkey := fs.String("signing-key", "", "private Ed25519 signing.key")
	cert := fs.String("tls-cert", "", "Beacon server.crt")
	tlskey := fs.String("tls-key", "", "Beacon server.key (never distribute)")
	listen := fs.String("listen", "127.0.0.1:8443", "HTTPS listen address")
	every := fs.Duration("sync-interval", 6*time.Hour, "source refresh interval")
	ttl := fs.Duration("ttl", 24*time.Hour, "signed snapshot lifetime, maximum 7 days")
	profile := fs.String("profile", "all", "public publication profile: all or prototype (Ubuntu 24.04, Debian 12, macOS)")
	base := fs.String("base-url", "", "immutable HTTPS artifact directory URL (for GitHub exports)")
	if e := fs.Parse(args[1:]); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if cmd == "release" {
		if *out == "" {
			*out = filepath.Join(*dir, "public")
		}
		key, err := identity.Private(*signkey)
		if err != nil {
			return err
		}
		pin, err := distribution.Release(*out, *binaries, buildinfo.Version, key, time.Now().UTC(), *releaseTTL)
		if err == nil {
			fmt.Println("Published signed agent installers. Trusted SPKI SHA256:", pin)
			fmt.Println("Trusted installer SHA256:", distribution.InstallerDigest())
		}
		return err
	}
	if cmd == "init" {
		if *pki == "" {
			return errors.New("-pki NEW_DIRECTORY is required")
		}
		if e := identity.Init(*pki, strings.Split(*hosts, ","), time.Now()); e != nil {
			return e
		}
		fmt.Println("Created TLS identity and independent signing key. Provision ca.crt and feed.pub to agents; keep private keys private.")
		return nil
	}
	if cmd != "sync" && cmd != "export" && cmd != "serve" && cmd != "run" && cmd != "news" && cmd != "status" && cmd != "check-sources" {
		return errors.New("unknown command")
	}
	if *out == "" {
		*out = filepath.Join(*dir, "public")
	}
	if *base != "" {
		u, e := url.Parse(*base)
		if e != nil || u.RawQuery != "" || !strings.HasSuffix(u.Path, "/") {
			return errors.New("base-url must be an HTTPS directory URL ending in /")
		}
		if e = netpolicy.URL(*base, []string{u.Hostname()}); e != nil {
			return e
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *policy != "" && (cmd == "sync" || cmd == "run") {
		if err := productid.Load(*policy); err != nil {
			return err
		}
	}
	var sources []source.Source
	if cmd == "sync" || cmd == "run" || cmd == "check-sources" {
		var e error
		sources, e = source.LoadWithDefaultVEX(*config, *defaultVEX)
		if e != nil {
			return e
		}
	}
	export := func() error {
		unlock, e := filelock.Acquire(ctx, filepath.Join(*dir, "sync.lock"), true)
		if e != nil {
			return e
		}
		defer unlock()
		key, e := identity.Private(*signkey)
		if e != nil {
			return e
		}
		summary, e := catalog.Publication(*dir)
		if e != nil {
			return e
		}
		started := time.Now()
		m, e := exporter.Export(ctx, *out, summary, key, *base, *ttl, time.Now())
		if e == nil {
			fmt.Printf("exported revision=%d objects=%d profile=%s publication=%s\n", m.Revision, len(m.Objects), m.Profile, time.Since(started).Round(time.Millisecond))
		}
		return e
	}
	update := func() error {
		summary, e := catalog.SyncWithWorkers(ctx, *dir, sources, compactdb.Profile(*profile), *retain, *sourceWorkers)
		if e != nil {
			return e
		}
		if e = printStatus(summary); e != nil {
			return e
		}
		if *signkey != "" {
			return export()
		}
		return nil
	}
	if cmd == "sync" || cmd == "check-sources" {
		return update()
	}
	if cmd == "status" {
		s, e := catalog.Load(*dir)
		if e != nil {
			return e
		}
		if e = printStatus(s); e != nil {
			return e
		}
		_, e = catalog.Publication(*dir)
		return e
	}
	if cmd == "news" {
		items, e := catalog.News(ctx, *dir)
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(items)
	}
	if cmd == "export" {
		return export()
	}

	if *cert == "" || *tlskey == "" {
		return errors.New("HTTPS requires -tls-cert and -tls-key")
	}
	if cmd == "run" && (*every < time.Second || *signkey == "") {
		return errors.New("run requires signing key and sync interval >=1s")
	}
	var workers sync.WaitGroup
	defer func() { stop(); workers.Wait() }()
	if cmd == "run" {
		// Validate the signing key before starting a long-running process.
		if _, e := identity.Private(*signkey); e != nil {
			return e
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				if e := update(); e != nil {
					log.Print(e)
				}
				timer := time.NewTimer(*every)
				select {
				case <-ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}()
	}
	// The TLS key is separate from the artifact signing key and CA signing key.
	info, e := os.Stat(*tlskey)
	if e != nil {
		return e
	}
	if info.Mode().Perm()&0077 != 0 {
		return errors.New("TLS private key must have mode 0600 or stricter")
	}
	handler := publish.Artifacts(*out)
	if *metadataSources != "" {
		raw, err := os.ReadFile(*metadataSources)
		if err != nil {
			return err
		}
		if len(raw) > 65536 {
			return errors.New("update sources config too large")
		}
		var cfg updategateway.Config
		if err = json.Unmarshal(raw, &cfg); err != nil {
			return err
		}
		gateway, err := updategateway.New(cfg)
		if err != nil {
			return err
		}
		mux := http.NewServeMux()
		mux.Handle("/v1/update-metadata", gateway)
		if *metadataCache != "" {
			mirror, err := updategateway.NewHomebrew(*metadataCache)
			if err != nil {
				return err
			}
			mux.Handle("/v1/homebrew/", mirror)
		}
		mux.Handle("/", handler)
		handler = mux
	}
	srv := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 2 * time.Minute, IdleTimeout: 30 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServeTLS(*cert, *tlskey) }()
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	case e := <-errc:
		if errors.Is(e, http.ErrServerClosed) {
			return nil
		}
		return e
	}
}

func printStatus(s catalog.Summary) error {
	return json.NewEncoder(os.Stdout).Encode(struct {
		Format  int                    `json:"format"`
		Profile compactdb.Profile      `json:"profile"`
		Rows    int64                  `json:"rows"`
		Bytes   int64                  `json:"bytes"`
		Buckets int                    `json:"buckets"`
		Sources []catalog.SourceStatus `json:"sources"`
	}{s.Format, s.Profile, s.Rows, s.Bytes, len(s.Buckets), s.Sources})
}
