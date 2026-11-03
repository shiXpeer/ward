package collect

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"shixpeer.com/ward/pkg/inventory"
	"strconv"
	"strings"
)

// Minimal Ubuntu installs need no extra packages to enumerate ports. Owner
// attribution remains unavailable in this fallback rather than guessing PIDs.
func procSockets(ctx context.Context, s *inventory.Snapshot) error {
	success := false
	for _, kind := range []string{"tcp", "tcp6", "udp", "udp6"} {
		if err := ctx.Err(); err != nil {
			return err
		}
		f, err := os.Open("/proc/net/" + kind)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		raw, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
		f.Close()
		if err != nil {
			return err
		}
		if len(raw) > 4<<20 {
			return fmt.Errorf("proc socket output exceeds limit")
		}
		if err = parseProcNet(string(raw), kind, s); err != nil {
			return err
		}
		success = true
	}
	if !success {
		return fmt.Errorf("no supported /proc/net socket tables")
	}
	s.AddNote(inventory.Unresolved, "socket-owners", "ss was unavailable; /proc/net fallback reports port bindings without process owners (install iproute2 for ss)")
	return nil
}
func parseProcNet(text, kind string, s *inventory.Snapshot) error {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || f[0] == "sl" {
			continue
		}
		if len(f) < 10 {
			return fmt.Errorf("invalid proc socket record")
		}
		tcp := strings.HasPrefix(kind, "tcp")
		if tcp && f[3] != "0A" || !tcp && f[3] != "07" {
			continue
		}
		address, port, ok := strings.Cut(f[1], ":")
		if !ok {
			return fmt.Errorf("invalid proc socket address")
		}
		raw, err := hex.DecodeString(address)
		if err != nil || len(raw) != 4 && len(raw) != 16 {
			return fmt.Errorf("invalid proc address encoding")
		}
		// Linux seq-file addresses are native little-endian u32 words on supported
		// amd64/arm64 builds, including each u32 within IPv6 addresses.
		for i := 0; i < len(raw); i += 4 {
			raw[i], raw[i+3] = raw[i+3], raw[i]
			raw[i+1], raw[i+2] = raw[i+2], raw[i+1]
		}
		p, err := strconv.ParseUint(port, 16, 16)
		if err != nil || p == 0 {
			continue
		}
		family := "IPv4"
		if len(raw) == 16 {
			family = "IPv6"
		}
		proto := "udp"
		if tcp {
			proto = "tcp"
		}
		if len(s.Listeners) >= maxRuntime {
			return fmt.Errorf("socket limit reached")
		}
		s.Listeners = append(s.Listeners, inventory.Listener{Family: family, Protocol: proto, Port: int(p), BindScope: bindScope(net.IP(raw).String()), Evidence: "proc-net", Reachability: "UNKNOWN"})
	}
	return nil
}
