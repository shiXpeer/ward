package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"shixpeer.com/ward/internal/atomicfile"
	"shixpeer.com/ward/internal/netpolicy"
	"shixpeer.com/ward/internal/reportrelay"
)

type enrollmentInput struct {
	URL       string `json:"url"`
	Token     string `json:"token"`
	ServerID  string `json:"server_id"`
	Recipient string `json:"recipient_public_key"`
}
type enrollmentCheckpoint struct {
	TicketHash string `json:"ticket_hash"`
	Nonce      string `json:"nonce"`
}

func enrollAgent(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	input := fs.String("enrollment-file", "", "private enrollment JSON file; - reads stdin")
	output := fs.String("out", "", "private report-upload.json destination")
	ca := fs.String("ca-file", "", "trusted relay CA file")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *input == "" || *output == "" || fs.NArg() != 0 {
		return errors.New("enroll requires -enrollment-file and -out")
	}
	var raw []byte
	var err error
	if *input == "-" {
		raw, err = io.ReadAll(io.LimitReader(os.Stdin, 16385))
	} else {
		f, e := os.Open(*input)
		if e != nil {
			return e
		}
		defer f.Close()
		raw, err = io.ReadAll(io.LimitReader(f, 16385))
	}
	if err != nil {
		return err
	}
	if len(raw) > 16384 {
		return errors.New("enrollment exceeds size limit")
	}
	var cfg enrollmentInput
	if err = json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	return enrollWith(ctx, cfg, *output, *ca)
}
func enrollWith(ctx context.Context, cfg enrollmentInput, output, ca string) error {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("invalid relay origin")
	}
	if err = netpolicy.URL(cfg.URL, []string{u.Hostname()}); err != nil {
		return err
	}
	token, e := hex.DecodeString(cfg.Token)
	if e != nil || len(token) != 32 {
		return errors.New("invalid enrollment token")
	}
	recipient, e := base64.StdEncoding.DecodeString(cfg.Recipient)
	if e != nil || len(recipient) != 32 || !validServerID(cfg.ServerID) {
		return errors.New("invalid enrollment identity")
	}
	var existing uploadConfig
	if err = atomicfile.ReadJSON(output, &existing, 16384); err == nil {
		if existing.URL == cfg.URL && existing.ID == cfg.ServerID && existing.Recipient == cfg.Recipient && len(existing.Token) >= 32 {
			return nil
		}
		return errors.New("agent is already connected to another server or recipient; refusing to overwrite its configuration")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	hash := sha256.Sum256([]byte(cfg.Token))
	hashText := hex.EncodeToString(hash[:])
	checkpoint := enrollmentCheckpoint{}
	err = atomicfile.ReadJSON(output+".enrollment", &checkpoint, 4096)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if checkpoint.TicketHash != hashText || len(checkpoint.Nonce) != 64 {
		nonce := make([]byte, 32)
		if _, err = rand.Read(nonce); err != nil {
			return err
		}
		checkpoint = enrollmentCheckpoint{hashText, hex.EncodeToString(nonce)}
		raw, _ := json.Marshal(checkpoint)
		if err = atomicfile.Write(output+".enrollment", raw, 0600); err != nil {
			return err
		}
	}
	client, err := netpolicy.Client(ca, []string{u.Hostname()})
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	body, _ := json.Marshal(map[string]string{"nonce": checkpoint.Nonce})
	req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(cfg.URL, "/")+"/v1/enrollments/redeem", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("relay enrollment failed; rerun the same command before expiry: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("relay enrollment returned HTTP %d; command may be expired, already used, or relay needs updating", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16385))
	if err != nil {
		return err
	}
	if len(data) > 16384 {
		return errors.New("enrollment response too large")
	}
	var credentials reportrelay.EnrollmentCredentials
	if err = json.Unmarshal(data, &credentials); err != nil {
		return err
	}
	if credentials.ServerID != cfg.ServerID || credentials.Recipient != cfg.Recipient || len(credentials.Writer) != 64 {
		return errors.New("relay enrollment identity mismatch")
	}
	result := uploadConfig{URL: cfg.URL, ID: cfg.ServerID, Token: credentials.Writer, Recipient: cfg.Recipient, CA: ca}
	data, err = json.Marshal(result)
	if err != nil {
		return err
	}
	if err = atomicfile.Write(output, data, 0600); err != nil {
		return err
	}
	_ = os.Remove(output + ".enrollment")
	fmt.Println("Relay connected. Encrypted reports will use server ID:", cfg.ServerID)
	return nil
}
func validServerID(id string) bool {
	if len(id) < 1 || len(id) > 64 {
		return false
	}
	for i, c := range []byte(id) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		if i == 0 || (c != '.' && c != '_' && c != '-') {
			return false
		}
	}
	return true
}
