package main

import (
	"flag"
	"log"
	"net/http"
	"path/filepath"
	"time"

	"shixpeer.com/ward/internal/atomicfile"
	"shixpeer.com/ward/internal/paths"
	"shixpeer.com/ward/internal/reportrelay"
)

func main() {
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
