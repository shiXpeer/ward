package firewall

import (
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
)

// VerifyNFT rejects native or mixed rulesets that iptables-save cannot
// represent. nft and iptables snapshots are taken in the same collection.
func (t Tables) VerifyNFT(other Tables, raw []byte) error {
	var doc struct {
		Objects []struct {
			Table     *nftTable
			Chain     *nftChain
			Rule      *nftRule
			Flowtable json.RawMessage
		} `json:"nftables"`
	}
	if json.Unmarshal(raw, &doc) != nil || doc.Objects == nil {
		return errors.New("nftables snapshot unavailable")
	}
	families := map[string]Tables{"ip": t, "ip6": other}
	counts := map[[3]string]int{}
	native := map[[2]string]bool{}
	names := map[[3]string]string{}
	nativeFamilies := func(family string) []Tables {
		switch family {
		case "ip":
			return []Tables{t}
		case "ip6":
			return []Tables{other}
		case "inet":
			return []Tables{t, other}
		}
		return nil
	}
	for _, object := range doc.Objects {
		if len(object.Flowtable) != 0 {
			return errors.New("nftables flowtable is active")
		}
		if table := object.Table; table != nil && families[table.Family][table.Name] == nil {
			if len(nativeFamilies(table.Family)) == 0 {
				return errors.New("unsupported nftables family is active")
			}
			native[[2]string{table.Family, table.Name}] = true
			for _, tables := range nativeFamilies(table.Family) {
				tables[nativeKey(table.Family, table.Name)] = map[string]*chain{}
			}
		}
		if c := object.Chain; c != nil {
			if native[[2]string{c.Family, c.Table}] {
				name, policy, err := nativeChain(c)
				if err != nil {
					return err
				}
				names[[3]string{c.Family, c.Table, c.Name}] = name
				for _, tables := range nativeFamilies(c.Family) {
					tables[nativeKey(c.Family, c.Table)][name] = &chain{policy: policy}
				}
				continue
			}
			chain := families[c.Family][c.Table][c.Name]
			if chain == nil || (c.Hook == "" && chain.policy != "-") ||
				(c.Hook != "" && (strings.ToUpper(c.Hook) != c.Name || strings.ToUpper(c.Policy) != chain.policy || !standardPriority(c.Table, c.Hook, c.Prio))) {
				return errors.New("unsupported nftables chain or hook priority")
			}
		}
		if r := object.Rule; r != nil {
			key := [3]string{r.Family, r.Table, r.Chain}
			if native[[2]string{r.Family, r.Table}] {
				parsed, err := nativeRule(r.Expr)
				if err != nil {
					return err
				}
				for _, tables := range nativeFamilies(r.Family) {
					c := tables[nativeKey(r.Family, r.Table)][names[key]]
					if c == nil {
						return errors.New("unaccounted native nftables rule")
					}
					c.rules = append(c.rules, parsed)
				}
			} else {
				counts[key]++
			}
		}
	}
	for family, tables := range families {
		for table, chains := range tables {
			if strings.HasPrefix(table, nativePrefix) {
				continue
			}
			for name, chain := range chains {
				key := [3]string{family, table, name}
				if counts[key] != len(chain.rules) {
					return errors.New("iptables and nftables rule inventories disagree")
				}
				delete(counts, key)
			}
		}
	}
	if len(counts) != 0 {
		return errors.New("nftables has unaccounted rules")
	}
	return nil
}

func standardPriority(table, hook string, priority int) bool {
	switch table {
	case "raw":
		return priority == -300
	case "mangle":
		return priority == -150
	case "filter":
		return priority == 0
	case "security":
		return priority == 50
	case "nat":
		if hook == "prerouting" || hook == "output" {
			return priority == -100
		}
		return priority == 100
	}
	return false
}

func (t Tables) HasRules() bool {
	for _, chains := range t {
		for _, chain := range chains {
			if len(chain.rules) != 0 || (chain.policy != "-" && chain.policy != "ACCEPT") {
				return true
			}
		}
	}
	return false
}

// SourceBoundaries partitions the address space into ranges on which every
// supported source-prefix match is constant.
func (t Tables) SourceBoundaries(ipv6 bool) []netip.Addr {
	first := netip.IPv4Unspecified()
	if ipv6 {
		first = netip.IPv6Unspecified()
	}
	boundaries := []netip.Addr{first}
	for _, chains := range t {
		for _, chain := range chains {
			for _, rule := range chain.rules {
				for i := 0; i+1 < len(rule); i++ {
					switch rule[i] {
					case "-s", "--source", "--ctorigsrc":
						if i > 0 && rule[i-1] == "--comment" {
							continue
						}
					default:
						continue
					}
					value := rule[i+1]
					prefix, err := netip.ParsePrefix(value)
					if err != nil {
						addr, err := netip.ParseAddr(value)
						if err != nil {
							continue
						}
						prefix = netip.PrefixFrom(addr, addr.BitLen())
					}
					if prefix.Addr().BitLen() != first.BitLen() {
						continue
					}
					prefix = prefix.Masked()
					last := prefix.Addr().AsSlice()
					for bit := prefix.Bits(); bit < len(last)*8; bit++ {
						last[bit/8] |= 1 << (7 - bit%8)
					}
					end, _ := netip.AddrFromSlice(last)
					boundaries = append(boundaries, prefix.Addr())
					if next := end.Next(); next.IsValid() {
						boundaries = append(boundaries, next)
					}
				}
			}
		}
	}
	slices.SortFunc(boundaries, netip.Addr.Compare)
	return slices.Compact(boundaries)
}
