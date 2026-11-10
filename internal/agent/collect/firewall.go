package collect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"

	"shixpeer.com/ward/internal/agent/firewall"
	"shixpeer.com/ward/pkg/inventory"
)

type firewallEndpoint struct {
	family, protocol, address, scope string
	port                             int
}

func (h Host) firewall(ctx context.Context, s *inventory.Snapshot) {
	if runtime.GOOS != "linux" {
		return
	}
	note := func(err error) {
		s.AddNote(inventory.Unresolved, "firewall", err.Error())
	}
	for _, family := range []string{"IPv4", "IPv6"} {
		flag := "-4"
		if family == "IPv6" {
			flag = "-6"
		}
		out, err := h.commandLimit(ctx, 1<<20, "ss", flag, "-H", "-lntupe")
		if err != nil {
			note(errors.New(family + " privileged listener inventory unavailable"))
			continue
		}
		for line := range strings.SplitSeq(string(out), "\n") {
			var sockets inventory.Snapshot
			if parseSS(line, &sockets) != nil {
				note(errors.New(family + " privileged listener output could not be parsed"))
				break
			}
			for _, socket := range sockets.Listeners {
				socket.Family = family
				s.Listeners = append(s.Listeners, socket)
				if family == "IPv6" && socket.BindScope == "wildcard" && strings.Contains(line, " v6only:0") {
					socket.Family, socket.BindAddress = "IPv4", "0.0.0.0"
					s.Listeners = append(s.Listeners, socket)
				}
				if len(s.Listeners) >= maxRuntime {
					note(errors.New("privileged listener budget exhausted"))
					return
				}
			}
		}
	}
	endpoints := map[firewallEndpoint]bool{}
	var ordered []firewallEndpoint
	add := func(p firewallEndpoint) {
		if p.scope == "wildcard" {
			p.address = ""
		}
		if !endpoints[p] {
			ordered = append(ordered, p)
			endpoints[p] = true
		}
	}
	for _, p := range s.Listeners {
		add(firewallEndpoint{p.Family, p.Protocol, p.BindAddress, p.BindScope, p.Port})
	}
	for _, c := range s.Containers {
		for _, p := range c.Ports {
			add(firewallEndpoint{p.Family, p.Protocol, p.BindAddress, p.BindScope, p.HostPort})
		}
	}
	tables, err := h.firewallTables(ctx)
	if err != nil {
		note(err)
	}
	ifaces, ifaceErr := net.Interfaces()
	addresses := map[string][]netip.Prefix{}
	if ifaceErr == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 {
				continue
			}
			list, addrErr := iface.Addrs()
			if addrErr != nil {
				ifaceErr = addrErr
				break
			}
			for _, addr := range list {
				if prefix, parseErr := netip.ParsePrefix(addr.String()); parseErr == nil {
					addresses[iface.Name] = append(addresses[iface.Name], prefix)
				}
			}
		}
	}
	if err == nil && ifaceErr != nil {
		err = errors.New("interface addresses unavailable")
	}
	for _, family := range []string{"IPv4", "IPv6"} {
		ipv6 := family == "IPv6"
		familyArg, forwardingPath := "-4", "/proc/sys/net/ipv4/ip_forward"
		if ipv6 {
			familyArg, forwardingPath = "-6", "/proc/sys/net/ipv6/conf/all/forwarding"
		}
		devices, routeErr := h.defaultInterfaces(ctx, familyArg)
		forwarding, forwardingErr := os.ReadFile(forwardingPath)
		if routeErr == nil {
			routeErr = h.standardRouting(ctx, familyArg)
		}
		routes := map[netip.Addr]string{}
		route := func(dest netip.Addr) string {
			if forwardingErr != nil {
				return ""
			}
			if cached, ok := routes[dest]; ok {
				return cached
			}
			if len(routes) >= 128 {
				return ""
			}
			raw, err := h.commandLimit(ctx, 64<<10, "ip", "-j", familyArg, "route", "get", dest.String())
			var found []struct {
				Dev, Type, Gateway string
				Nexthops           []json.RawMessage
			}
			routes[dest] = ""
			if err != nil || json.Unmarshal(raw, &found) != nil || len(found) != 1 {
				return ""
			}
			entry := found[0]
			if len(entry.Nexthops) != 0 || entry.Gateway != "" || (entry.Type != "" && entry.Type != "local" && entry.Type != "unicast") {
				return ""
			}
			routes[dest] = entry.Dev
			return entry.Dev
		}
		table := tables[family]
		boundaries := table.SourceBoundaries(ipv6)
		remaining := 16384
		for _, p := range ordered {
			if ctx.Err() != nil {
				return
			}
			if p.family != family {
				continue
			}
			v := inventory.FirewallVerdict{Port: p.port, Protocol: p.protocol, Family: family, Status: "UNKNOWN"}
			switch {
			case p.scope == "loopback":
				// Loopback listeners can still be exposed through a redirect or proxy.
				v.Reason = "loopback bind; external forwarding to this socket was not evaluated"
			case err != nil:
				v.Reason = err.Error()
			case routeErr != nil:
				v.Reason = routeErr.Error()
			case len(boundaries) > 256:
				v.Reason = "source policy exceeds evaluation budget"
			default:
				for _, dev := range devices {
					for _, prefix := range addresses[dev] {
						addr := prefix.Addr()
						if addr.Is6() != ipv6 || !addr.IsGlobalUnicast() || (p.scope != "wildcard" && p.address != addr.String()) {
							continue
						}
						if remaining < len(boundaries) {
							break
						}
						remaining -= len(boundaries)
						v.Interface, v.Destination = dev, addr.String()
						s.Firewall = append(s.Firewall, firewallRanges(table, boundaries, v, addr, route, strings.TrimSpace(string(forwarding)) == "1")...)
					}
				}
				if v.Destination != "" && remaining >= len(boundaries) {
					continue
				}
				v.Interface, v.Destination = "", ""
				v.Reason = "no matching address on a default-route interface or evaluation budget exhausted"
			}
			s.Firewall = append(s.Firewall, v)
		}
	}
}

func firewallRanges(t firewall.Tables, bounds []netip.Addr, base inventory.FirewallVerdict, addr netip.Addr, route func(netip.Addr) string, forwarding bool) []inventory.FirewallVerdict {
	var out []inventory.FirewallVerdict
	last := netip.MustParseAddr("255.255.255.255")
	if addr.Is6() {
		last = netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	}
	for i, source := range bounds {
		r := t.Evaluate(firewall.Packet{Source: source, Destination: addr, Port: base.Port, Protocol: base.Protocol, In: base.Interface, Local: true, Output: route}, forwarding)
		v := base
		end := last
		if i+1 < len(bounds) {
			end = bounds[i+1].Prev()
		}
		v.SourceFirst, v.SourceLast = source.String(), end.String()
		v.Status, v.Path, v.Reason = r.Status, r.Path, r.Reason
		if len(out) != 0 {
			prev := &out[len(out)-1]
			if prev.Status == v.Status && prev.Path == v.Path && prev.Reason == v.Reason {
				prev.SourceLast = v.SourceLast
				continue
			}
		}
		out = append(out, v)
	}
	return out
}

func (h Host) standardRouting(ctx context.Context, family string) error {
	raw, err := h.commandLimit(ctx, 128<<10, "ip", "-j", family, "rule", "show")
	var rules []map[string]json.RawMessage
	if err != nil || json.Unmarshal(raw, &rules) != nil || len(rules) < 2 {
		return errors.New("policy routing snapshot unavailable")
	}
	expected := map[int]string{0: "local", 32766: "main", 32767: "default"}
	for _, rule := range rules {
		var priority int
		var source, table string
		if len(rule) != 3 || json.Unmarshal(rule["priority"], &priority) != nil || json.Unmarshal(rule["src"], &source) != nil ||
			json.Unmarshal(rule["table"], &table) != nil || source != "all" || expected[priority] != table {
			return errors.New("non-default policy routing is outside the local firewall model")
		}
		delete(expected, priority)
	}
	if expected[0] != "" || expected[32766] != "" {
		return errors.New("required standard routing rules are missing")
	}
	return nil
}

func (h Host) defaultInterfaces(ctx context.Context, family string) ([]string, error) {
	out, err := h.commandLimit(ctx, 1<<20, "ip", "-j", family, "route", "show", "default")
	var routes []struct {
		Dev      string
		Nexthops []struct{ Dev string }
	}
	if err != nil || json.Unmarshal(out, &routes) != nil {
		return nil, errors.New("default ingress interfaces unavailable")
	}
	var devices []string
	seen := map[string]bool{}
	for _, r := range routes {
		if len(r.Nexthops) != 0 {
			return nil, errors.New("multipath ingress routing is unsupported")
		}
		if r.Dev != "" && !seen[r.Dev] {
			devices = append(devices, r.Dev)
			seen[r.Dev] = true
		}
	}
	return devices, nil
}

func (h Host) firewallTables(ctx context.Context) (map[string]firewall.Tables, error) {
	read := func(name string) (firewall.Tables, error) {
		raw, err := h.commandLimit(ctx, 2<<20, name)
		if err != nil {
			return nil, fmt.Errorf("%s snapshot unavailable", name)
		}
		return firewall.Parse(string(raw))
	}
	v4, err := read("iptables-nft-save")
	if err != nil {
		return nil, err
	}
	v6, err := read("ip6tables-nft-save")
	if err != nil {
		return nil, err
	}
	nft, err := h.commandLimit(ctx, 4<<20, "nft", "-j", "list", "ruleset")
	if err != nil {
		return nil, errors.New("nftables snapshot unavailable")
	}
	if err := v4.VerifyNFT(v6, nft); err != nil {
		return nil, err
	}
	for i, name := range []string{"iptables-legacy-save", "ip6tables-legacy-save"} {
		legacy, err := read(name)
		if err != nil {
			return nil, err
		}
		if !legacy.HasRules() {
			continue
		}
		target := &v4
		if i == 1 {
			target = &v6
		}
		if (*target).HasRules() {
			return nil, errors.New("mixed legacy and nft firewall paths are unsupported")
		}
		*target = legacy
	}
	return map[string]firewall.Tables{"IPv4": v4, "IPv6": v6}, nil
}
