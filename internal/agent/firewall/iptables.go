// Package firewall evaluates a bounded subset of Linux ingress rules.
// An unsupported rule on the evaluated path makes that path unknown.
package firewall

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

type rule []string
type chain struct {
	policy string
	rules  []rule
}
type Tables map[string]map[string]*chain

type Packet struct {
	Source, Destination, Original netip.Addr
	Port, OriginalPort            int
	Protocol, In, Out             string
	Local                         bool
	// Output resolves the interface of a translated destination.
	Output func(netip.Addr) string
}

type Result struct {
	Status string
	Path   string
	Reason string
}

func Parse(text string) (Tables, error) {
	tables := Tables{}
	var chains map[string]*chain
	for line := range strings.SplitSeq(text, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "*") && chains == nil:
			name := line[1:]
			if tables[name] != nil {
				return nil, fmt.Errorf("duplicate table %s", name)
			}
			chains = map[string]*chain{}
			tables[name] = chains
		case line == "COMMIT" && chains != nil:
			chains = nil
		case strings.HasPrefix(line, ":") && chains != nil:
			f := strings.Fields(line[1:])
			if len(f) != 3 || chains[f[0]] != nil {
				return nil, fmt.Errorf("invalid chain declaration")
			}
			chains[f[0]] = &chain{policy: f[1]}
		case strings.HasPrefix(line, "-A ") && chains != nil:
			f, err := fields(line)
			if err != nil || len(f) < 3 || chains[f[1]] == nil {
				return nil, fmt.Errorf("invalid rule in saved tables")
			}
			chains[f[1]].rules = append(chains[f[1]].rules, f[2:])
		default:
			return nil, fmt.Errorf("unexpected saved tables syntax")
		}
	}
	if chains != nil {
		return nil, fmt.Errorf("incomplete table snapshot")
	}
	return tables, nil
}

// iptables-save double-quotes comments and escapes characters inside them.
func fields(line string) ([]string, error) {
	var fields []string
	var token strings.Builder
	quoted, escaped, started := false, false, false
	for _, c := range line {
		switch {
		case escaped:
			token.WriteRune(c)
			escaped = false
		case c == '\\' && quoted:
			escaped = true
		case c == '"':
			quoted = !quoted
			started = true
		case (c == ' ' || c == '\t') && !quoted:
			if started {
				fields = append(fields, token.String())
				token.Reset()
				started = false
			}
		default:
			token.WriteRune(c)
			started = true
		}
	}
	if quoted || escaped {
		return nil, fmt.Errorf("unterminated quote")
	}
	if started {
		fields = append(fields, token.String())
	}
	return fields, nil
}

func ipMatch(value string, ip netip.Addr) (bool, bool) {
	if p, err := netip.ParsePrefix(value); err == nil {
		return p.Contains(ip), ip.IsValid()
	}
	a, err := netip.ParseAddr(value)
	return a == ip, err == nil && ip.IsValid()
}

func portsMatch(value string, port int) (bool, bool) {
	match := false
	for item := range strings.SplitSeq(value, ",") {
		a, b, rangePort := strings.Cut(item, ":")
		if !rangePort {
			b = a
		}
		if a == "" && rangePort {
			a = "0"
		}
		if b == "" && rangePort {
			b = "65535"
		}
		low, e1 := strconv.Atoi(a)
		high, e2 := strconv.Atoi(b)
		if e1 != nil || e2 != nil || low < 0 || high > 65535 || low > high {
			return false, false
		}
		match = match || (port >= low && port <= high)
	}
	return match, true
}

func (r rule) match(p Packet) (bool, bool, string, []string, bool) {
	known, negate := true, false
	for i := 0; i < len(r); i++ {
		option := r[i]
		if option == "!" {
			negate = !negate
			continue
		}
		if i+1 >= len(r) {
			return true, false, "", nil, false
		}
		i++
		v := r[i]
		match, understood := false, true
		switch option {
		case "-j", "-g":
			return true, known && !negate, v, r[i+1:], option == "-g"
		case "-s", "--source":
			match, understood = ipMatch(v, p.Source)
		case "-d", "--destination":
			match, understood = ipMatch(v, p.Destination)
		case "--ctorigdst":
			match, understood = ipMatch(v, p.Original)
		case "--ctorigsrc":
			match, understood = ipMatch(v, p.Source)
		case "--ctorigdstport":
			match, understood = portsMatch(v, p.OriginalPort)
		case "--dport", "--destination-port", "--dports":
			match, understood = portsMatch(v, p.Port)
		case "--family":
			match = (v == "ip6") == p.Destination.Is6()
		case "-p":
			match = v == p.Protocol || v == "all" || v == "0" || (v == "6" && p.Protocol == "tcp") || (v == "17" && p.Protocol == "udp")
		case "-i", "-o":
			iface := p.In
			if option == "-o" {
				iface = p.Out
			}
			match = v == iface || (strings.HasSuffix(v, "+") && strings.HasPrefix(iface, strings.TrimSuffix(v, "+")))
			understood = iface != ""
		case "--ctstate", "--state":
			match = strings.Contains(","+v+",", ",NEW,") || (p.Destination != p.Original || p.Port != p.OriginalPort) && strings.Contains(","+v+",", ",DNAT,")
		case "--ctdir":
			match, understood = v == "ORIGINAL", v == "ORIGINAL" || v == "REPLY"
		case "--dst-type":
			match, understood = p.Local, v == "LOCAL"
		case "--limit", "--limit-burst":
			understood = false
		case "--comment":
			match = true
		case "-m":
			switch v {
			case "tcp", "udp", "multiport", "comment", "conntrack", "state", "addrtype":
				match = true
			default:
				understood = false
			}
		default:
			// Unknown flags may not take a value. Don't consume the
			// next option and accidentally skip a known contradiction.
			understood = false
			if strings.HasPrefix(v, "-") || v == "!" {
				i--
			}
		}
		if understood && match == negate {
			return false, true, "", nil, false
		}
		known = known && understood
		negate = false
	}
	return true, false, "", nil, false
}

// A rate-limited log target affects diagnostics, not ingress policy.
func (r rule) logOnly() bool {
	for i := 0; i+1 < len(r); i++ {
		switch r[i] {
		case "-m":
			i++
			switch r[i] {
			case "limit", "comment", "tcp", "udp", "multiport", "conntrack", "state", "addrtype":
			default:
				return false
			}
		case "-j":
			return true
		}
	}
	return false
}

func (t Tables) walk(table, name string, p *Packet, depth int, budget *int) (string, string) {
	c := t[table][name]
	if c == nil || depth > 16 {
		return "UNKNOWN", table + "/" + name + " chain unavailable or recursion limit"
	}
	for i, r := range c.rules {
		*budget--
		at := fmt.Sprintf("%s/%s rule %d", table, name, i+1)
		if *budget < 0 {
			return "UNKNOWN", "rule evaluation budget exhausted"
		}
		matches, known, action, args, goTo := r.match(*p)
		if !matches {
			continue
		}
		if !known {
			return "UNKNOWN", at + " has an unsupported condition"
		}
		switch action {
		case "ACCEPT", "DROP", "REJECT", "RETURN":
			if len(args) != 0 && action != "REJECT" {
				return "UNKNOWN", at + " unsupported target options"
			}
			return action, at
		case "LOG", "NFLOG", "CONTINUE":
			continue
		case "DNAT":
			if table != "nat" || len(args) != 2 || args[0] != "--to-destination" {
				return "UNKNOWN", at + " unsupported DNAT target"
			}
			addr, port, err := translated(args[1], p.Port)
			if err != nil || addr.BitLen() != p.Destination.BitLen() {
				return "UNKNOWN", at + " unsupported DNAT destination"
			}
			p.Destination, p.Port = addr, port
			return action, at
		default:
			if len(args) != 0 {
				return "UNKNOWN", at + " unsupported target options"
			}
			verdict, reason := t.walk(table, action, p, depth+1, budget)
			if verdict != "RETURN" || goTo {
				return verdict, reason
			}
		}
	}
	return "RETURN", table + "/" + name + " policy"
}

func translated(value string, original int) (netip.Addr, int, error) {
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr, original, nil
	}
	ap, err := netip.ParseAddrPort(value)
	if err != nil || ap.Port() == 0 {
		return netip.Addr{}, 0, fmt.Errorf("invalid DNAT destination")
	}
	return ap.Addr(), int(ap.Port()), nil
}

func (t Tables) Evaluate(p Packet, forwarding bool) Result {
	p.Original, p.OriginalPort = p.Destination, p.Port
	path := "INPUT"
	budget := 10000
	hook := func(table, name string) (string, string) {
		c := t[table][name]
		if c == nil {
			return "ACCEPT", table + "/" + name + " has no chain"
		}
		verdict, reason := t.walk(table, name, &p, 0, &budget)
		if verdict == "RETURN" {
			verdict, reason = c.policy, table+"/"+name+" policy "+c.policy
		}
		return verdict, reason
	}
	result := func(v, reason string) Result {
		status := "UNKNOWN"
		switch v {
		case "DROP", "REJECT":
			status = "BLOCKED"
		case "ACCEPT":
			status = "ALLOWED"
		}
		return Result{status, path, reason}
	}
	for _, table := range []string{"raw", "mangle", "nat"} {
		v, why := hook(table, "PREROUTING")
		if v == "DNAT" && table == "nat" {
			path = fmt.Sprintf("DNAT %s → %s", netip.AddrPortFrom(p.Original, uint16(p.OriginalPort)), netip.AddrPortFrom(p.Destination, uint16(p.Port)))
			p.Out = p.Output(p.Destination)
			p.Local = p.Out == "lo"
			if p.Out == "" {
				return result("UNKNOWN", "route to DNAT destination is unknown")
			}
			if !p.Local {
				path += " / FORWARD"
				if !forwarding {
					return result("DROP", "IP forwarding disabled")
				}
			} else {
				path += " / INPUT"
			}
			break
		}
		if v != "ACCEPT" {
			return result(v, why)
		}
	}
	chain := "INPUT"
	if !p.Local {
		chain = "FORWARD"
	}
	last := ""
	for _, table := range []string{"mangle", "filter", "security", "nat"} {
		if table == "nat" && chain == "FORWARD" {
			continue
		}
		v, why := hook(table, chain)
		if v != "ACCEPT" {
			return result(v, why)
		}
		if t[table][chain] != nil {
			last = why
		}
	}
	for _, table := range slices.Sorted(maps.Keys(t)) {
		if !strings.HasPrefix(table, nativePrefix) {
			continue
		}
		for _, name := range slices.Sorted(maps.Keys(t[table])) {
			if !strings.HasPrefix(name, chain+"/") {
				continue
			}
			v, why := hook(table, name)
			if v != "ACCEPT" {
				return result(v, why)
			}
			last = why
		}
	}
	if last == "" {
		last = "no ingress filter chain"
	}
	return result("ACCEPT", last)
}
