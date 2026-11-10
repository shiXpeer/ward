package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"
)

// probeTCP is explicitly invoked on an operator-controlled external host.
func probeTCP(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	target := fs.String("target", "", "numeric IPv4:port or [IPv6]:port")
	source := fs.String("source", "", "optional local source IP")
	timeout := fs.Duration("timeout", 3*time.Second, "connection timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	addr, err := netip.ParseAddrPort(*target)
	if err != nil || addr.Port() == 0 || addr.Addr().IsUnspecified() || addr.Addr().IsMulticast() || fs.NArg() != 0 {
		return errors.New("probe requires a numeric unicast -target with a nonzero TCP port")
	}
	if *timeout <= 0 || *timeout > 30*time.Second {
		return errors.New("probe timeout must be greater than zero and at most 30s")
	}
	dialer := net.Dialer{Timeout: *timeout}
	if *source != "" {
		ip, err := netip.ParseAddr(*source)
		if err != nil || ip.IsUnspecified() || ip.IsMulticast() || ip.Unmap().Is4() != addr.Addr().Unmap().Is4() {
			return errors.New("probe source must be a local unicast IP of the target address family")
		}
		dialer.LocalAddr = &net.TCPAddr{IP: ip.AsSlice(), Zone: ip.Zone()}
	}
	result := struct {
		Target string    `json:"target"`
		Source string    `json:"local_source,omitempty"`
		Status string    `json:"status"`
		At     time.Time `json:"checked_at"`
	}{Target: addr.String(), Source: *source}
	conn, err := dialer.DialContext(context.Background(), "tcp", addr.String())
	switch {
	case err == nil:
		result.Source = conn.LocalAddr().String()
		conn.Close()
		result.Status = "CONNECTED"
	case errors.Is(err, syscall.ECONNREFUSED):
		result.Status = "REFUSED"
	case errors.Is(err, os.ErrDeadlineExceeded):
		result.Status = "TIMEOUT"
	default:
		result.Status = "UNKNOWN"
	}
	result.At = time.Now().UTC()
	return json.NewEncoder(os.Stdout).Encode(result)
}
