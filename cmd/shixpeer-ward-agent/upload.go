package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"shixpeer.com/ward/internal/atomicfile"
	"shixpeer.com/ward/internal/netpolicy"
	"shixpeer.com/ward/internal/reportrelay"
)

type uploadConfig struct {
	URL       string `json:"url"`
	ID        string `json:"server_id"`
	Token     string `json:"writer_token"`
	Recipient string `json:"recipient_public_key"`
	CA        string `json:"ca_file"`
}

func uploadReport(ctx context.Context, config, report string) error {
	var cfg uploadConfig
	if err := atomicfile.ReadJSON(config, &cfg, 16384); err != nil {
		return err
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || u.RawQuery != "" || u.Fragment != "" || len(cfg.Token) < 32 {
		return errors.New("invalid relay settings")
	}
	hosts := []string{u.Hostname()}
	if err = netpolicy.URL(cfg.URL, hosts); err != nil {
		return err
	}
	recipient, err := base64.StdEncoding.DecodeString(cfg.Recipient)
	if err != nil {
		return err
	}
	f, err := os.Open(report)
	if err != nil {
		return err
	}
	defer f.Close()
	plain, err := io.ReadAll(io.LimitReader(f, reportrelay.MaxReport+1))
	if err != nil {
		return err
	}
	sealed, err := reportrelay.Seal(recipient, plain, cfg.ID)
	if err != nil {
		return err
	}
	c, err := netpolicy.Client(cfg.CA, hosts)
	if err != nil {
		return err
	}
	defer c.CloseIdleConnections()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequestWithContext(ctx, "PUT", strings.TrimRight(cfg.URL, "/")+"/v1/reports/"+cfg.ID, bytes.NewReader(sealed))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 204 {
		return fmt.Errorf("relay returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func sendReport(ctx context.Context, config, dir, dest string) error {
	if config == "" {
		return nil
	}
	if dest == "" {
		dest = dir
	}
	return uploadReport(ctx, config, filepath.Join(dest, "report.json"))
}
