package firewall

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type nftChain struct {
	Family, Table, Name, Hook, Policy, Type, Dev string
	Prio                                         int
}

type nftRule struct {
	Family, Table, Chain string
	Expr                 []map[string]json.RawMessage
}

type nftTable struct{ Family, Name string }

const nativePrefix = "nft:"

func nativeKey(family, table string) string { return nativePrefix + family + ":" + table }

func nativeChain(c *nftChain) (string, string, error) {
	if c.Hook == "" {
		return c.Name, "-", nil
	}
	if c.Type != "filter" || c.Dev != "" || (c.Hook != "input" && c.Hook != "forward") {
		return "", "", errors.New("unsupported native nftables hook (only input/forward filter chains are modeled)")
	}
	policy := strings.ToUpper(c.Policy)
	if policy != "ACCEPT" && policy != "DROP" {
		return "", "", errors.New("unsupported native nftables policy")
	}
	return strings.ToUpper(c.Hook) + "/" + c.Name, policy, nil
}

func nativeRule(expr []map[string]json.RawMessage) (rule, error) {
	var out rule
	terminal := false
	for _, e := range expr {
		if len(e) != 1 || terminal {
			return nil, errors.New("unsupported native nftables expression sequence")
		}
		for k, raw := range e {
			switch k {
			case "counter", "log", "comment":
			case "match":
				match, err := nativeMatch(raw)
				if err != nil {
					return nil, err
				}
				out = append(out, match...)
			case "accept", "drop", "reject", "return", "continue":
				out = append(out, "-j", strings.ToUpper(k))
				terminal = true
			case "jump", "goto":
				var target struct{ Target string }
				if json.Unmarshal(raw, &target) != nil || target.Target == "" {
					return nil, errors.New("invalid native nftables chain target")
				}
				flag := "-j"
				if k == "goto" {
					flag = "-g"
				}
				out = append(out, flag, target.Target)
				terminal = true
			default:
				return nil, fmt.Errorf("unsupported native nftables %s expression", k)
			}
		}
	}
	if !terminal {
		out = append(out, "-j", "CONTINUE")
	}
	return out, nil
}

func nativeMatch(raw json.RawMessage) (rule, error) {
	var m struct {
		Op   string
		Left struct {
			Meta    *struct{ Key string }
			Payload *struct{ Protocol, Field string }
			CT      *struct{ Key, Dir string }
		}
		Right json.RawMessage
	}
	unsupported := errors.New("unsupported native nftables match")
	if json.Unmarshal(raw, &m) != nil || (m.Op != "==" && m.Op != "!=" && m.Op != "in") {
		return nil, unsupported
	}
	var out rule
	var option string
	var value string
	requiresProtocol := ""
	switch {
	case m.Left.Meta != nil:
		switch m.Left.Meta.Key {
		case "iifname":
			option = "-i"
		case "oifname":
			option = "-o"
		case "l4proto":
			option = "-p"
		default:
			return nil, unsupported
		}
		if json.Unmarshal(m.Right, &value) != nil && option == "-p" {
			var number int
			if json.Unmarshal(m.Right, &number) == nil {
				value = strconv.Itoa(number)
			}
		}
		if value == "" || ((option == "-i" || option == "-o") && strings.ContainsAny(value, "*+")) {
			return nil, unsupported
		}
	case m.Left.Payload != nil:
		p := m.Left.Payload
		switch {
		case (p.Protocol == "ip" || p.Protocol == "ip6") && (p.Field == "saddr" || p.Field == "daddr"):
			option = "-s"
			if p.Field == "daddr" {
				option = "-d"
			}
			if json.Unmarshal(m.Right, &value) != nil {
				var right struct {
					Prefix *struct {
						Addr string
						Len  int
					}
				}
				if json.Unmarshal(m.Right, &right) != nil || right.Prefix == nil {
					return nil, unsupported
				}
				value = fmt.Sprintf("%s/%d", right.Prefix.Addr, right.Prefix.Len)
			}
			ipv6 := p.Protocol == "ip6"
			if addr, err := netip.ParseAddr(value); err == nil {
				if addr.Is6() != ipv6 {
					return nil, unsupported
				}
			} else if prefix, err := netip.ParsePrefix(value); err != nil || prefix.Addr().Is6() != ipv6 {
				return nil, unsupported
			}
			out = append(out, "--family", p.Protocol)
		case (p.Protocol == "tcp" || p.Protocol == "udp") && p.Field == "dport":
			option, requiresProtocol = "--dport", p.Protocol
			var port uint16
			if json.Unmarshal(m.Right, &port) == nil && port != 0 {
				value = strconv.Itoa(int(port))
			} else {
				var right struct{ Set []uint16 }
				if json.Unmarshal(m.Right, &right) != nil || len(right.Set) == 0 {
					return nil, unsupported
				}
				ports := make([]string, 0, len(right.Set))
				for _, p := range right.Set {
					ports = append(ports, strconv.Itoa(int(p)))
				}
				value = strings.Join(ports, ",")
			}
		default:
			return nil, unsupported
		}
	case m.Left.CT != nil && m.Left.CT.Key == "state" && m.Left.CT.Dir == "":
		option = "--ctstate"
		var states []string
		if json.Unmarshal(m.Right, &states) != nil {
			var right struct{ Set []string }
			if json.Unmarshal(m.Right, &right) == nil && len(right.Set) != 0 {
				states = right.Set
			} else {
				var state string
				if json.Unmarshal(m.Right, &state) != nil {
					return nil, unsupported
				}
				states = []string{state}
			}
		}
		for _, s := range states {
			switch s {
			case "new", "established", "related", "invalid", "untracked":
			default:
				return nil, unsupported
			}
		}
		value = strings.ToUpper(strings.Join(states, ","))
	default:
		return nil, unsupported
	}
	if requiresProtocol != "" {
		out = append(out, "-p", requiresProtocol)
	}
	if m.Op == "!=" {
		out = append(out, "!")
	}
	return append(out, option, value), nil
}
