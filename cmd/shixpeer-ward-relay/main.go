package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"shixpeer.com/ward/internal/atomicfile"
	"shixpeer.com/ward/internal/netpolicy"
	"shixpeer.com/ward/internal/paths"
	"shixpeer.com/ward/internal/reportrelay"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "check" {
		if err := checkRelay(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	if len(os.Args) > 1 && (os.Args[1] == "enable-enrollment" || os.Args[1] == "enrollment-token") {
		if err := configureEnrollment(os.Args[1], os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	config := flag.String("config", paths.Config("relay"), "private token configuration")
	dir := flag.String("state", filepath.Join(paths.State("relay"), "sealed"), "ciphertext directory")
	listen := flag.String("listen", "127.0.0.1:8444", "HTTPS listen address")
	cert := flag.String("tls-cert", "", "TLS certificate")
	key := flag.String("tls-key", "", "TLS private key")
	flag.Parse()
	if *cert == "" || *key == "" {
		log.Fatal("TLS certificate and key required")
	}
	var cfg reportrelay.Config
	if err := atomicfile.ReadJSON(*config, &cfg, 1<<20); err != nil {
		log.Fatal(err)
	}
	handler, err := cfg.Handler(*dir)
	if err != nil {
		log.Fatal(err)
	}
	server := http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 45 * time.Second, WriteTimeout: 45 * time.Second, IdleTimeout: time.Minute}
	log.Fatal(server.ListenAndServeTLS(*cert, *key))
}

func configureEnrollment(command string, args []string) error {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	path := fs.String("config", paths.Config("relay"), "private relay configuration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	var cfg reportrelay.Config
	if err := atomicfile.ReadJSON(*path, &cfg, 1<<20); err != nil {
		return err
	}
	if len(cfg.Reader) < 32 {
		return errors.New("invalid reader token")
	}
	if command == "enrollment-token" {
		if len(cfg.Enrollment) < 32 {
			return errors.New("enable enrollment and restart the relay first")
		}
		fmt.Println(cfg.Enrollment)
		return nil
	}
	if cfg.Enrollment != "" {
		if len(cfg.Enrollment) < 32 || cfg.Enrollment == cfg.Reader {
			return errors.New("invalid enrollment management token")
		}
		for _, token := range cfg.Writers {
			if token == cfg.Enrollment {
				return errors.New("management token must differ from writer tokens")
			}
		}
		fmt.Println("Enrollment management is already enabled.")
		return nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return err
	}
	cfg.Enrollment = hex.EncodeToString(raw)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err = atomicfile.Write(*path, data, 0600); err != nil {
		return err
	}
	fmt.Println("Enrollment management enabled. Restart the relay to activate it.")
	return nil
}

// check verifies authenticated HTTPS before displaying connection credentials.
func checkRelay(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	config := fs.String("config", paths.Config("relay"), "private relay configuration")
	origin := fs.String("url", "", "public HTTPS relay origin")
	ca := fs.String("ca-file", "", "public relay CA/certificate")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	var cfg reportrelay.Config
	if err := atomicfile.ReadJSON(*config, &cfg, 1<<20); err != nil {
		return err
	}
	u, err := url.Parse(*origin)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("invalid HTTPS relay origin")
	}
	if len(cfg.Reader) < 32 || len(cfg.Enrollment) < 32 {
		return errors.New("relay credentials are not configured")
	}
	client, err := netpolicy.Client(*ca, []string{u.Hostname()})
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if err = netpolicy.URL(*origin, []string{u.Hostname()}); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(*origin, "/")+"/v1/reports", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Reader)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("relay readiness returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if err != nil {
		return err
	}
	var ids []string
	if len(data) > 1<<20 || json.Unmarshal(data, &ids) != nil {
		return errors.New("invalid relay readiness response")
	}
	fmt.Println("Relay ready:", *origin)
	fmt.Println("Reader token:", cfg.Reader)
	fmt.Println("Enrollment token:", cfg.Enrollment)
	return nil
}
