package source

import (
	"compress/bzip2"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"regexp"
	"strings"

	"shixpeer.com/ward/internal/compactdb"
)

const JammyOVALProjectionRevision = 1
const JammyOVALKind = "ubuntu-jammy-oval-bzip2"
const jammyOVALPrefix = "oval:com.ubuntu.jammy:"
const unameNamespace = "http://oval.mitre.org/XMLSchema/oval-definitions-5#unix"

type ovalCriterion struct {
	Test    string `xml:"test_ref,attr"`
	Comment string `xml:"comment,attr"`
	Negate  string `xml:"negate,attr"`
}

type ovalCriteria struct {
	Operator string          `xml:"operator,attr"`
	Negate   string          `xml:"negate,attr"`
	Checks   []ovalCriterion `xml:"criterion"`
	Groups   []ovalCriteria  `xml:"criteria"`
	Extends  []struct {
		Ref           string `xml:"definition_ref,attr"`
		Applicability string `xml:"applicability_check,attr"`
		Negate        string `xml:"negate,attr"`
	} `xml:"extend_definition"`
}

func ovalPositive(negate string) bool { return negate == "" || negate == "false" }

func streamJammyOVAL(ctx context.Context, f io.ReadSeeker, emit func(Advisory) error) error {
	decoder := func() *xml.Decoder {
		return xml.NewDecoder(&checkedReader{ctx: ctx, r: bzip2.NewReader(f), left: 512 << 20})
	}
	tests, states := map[string]string{}, map[string]string{}
	packages := ovalPackageIndex{map[string][2]string{}, map[string]ovalEntity{}, map[string]string{}, map[string][]string{}}
	d := decoder()
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		e, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if e.Name.Space != unameNamespace {
			if err := packages.read(d, e); err != nil {
				return err
			}
			if len(packages.tests)+len(packages.objects)+len(packages.states)+len(packages.variables) > 1500000 {
				return errors.New("Ubuntu OVAL package index limit exceeded")
			}
			continue
		}
		switch e.Name.Local {
		case "uname_test":
			var t struct {
				ID        string `xml:"id,attr"`
				Check     string `xml:"check,attr"`
				Existence string `xml:"check_existence,attr"`
				Objects   []struct {
					Ref string `xml:"object_ref,attr"`
				} `xml:"object"`
				States []struct {
					Ref string `xml:"state_ref,attr"`
				} `xml:"state"`
			}
			if err := d.DecodeElement(&t, &e); err != nil {
				return err
			}
			if t.Check == "at least one" && t.Existence == "at_least_one_exists" && len(t.Objects) == 1 && t.Objects[0].Ref == jammyOVALPrefix+"obj:200" && len(t.States) == 1 {
				tests[t.ID] = t.States[0].Ref
			}
		case "uname_state":
			// Reject states with extra constraints, variables or entity attributes.
			id, pattern, err := readOVALUnameState(d, e)
			if err != nil {
				return err
			}
			if pattern != "" {
				states[id] = pattern
			}
		}
		if len(tests) > 500000 || len(states) > 500000 {
			return errors.New("Ubuntu OVAL kernel rule limit exceeded")
		}
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	d = decoder()
	count := 0
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		e, ok := token.(xml.StartElement)
		if !ok || e.Name.Local != "definition" || e.Name.Space != "http://oval.mitre.org/XMLSchema/oval-definitions-5" {
			continue
		}
		var def struct {
			ID    string `xml:"id,attr"`
			Class string `xml:"class,attr"`
			Refs  []struct {
				Source string `xml:"source,attr"`
				ID     string `xml:"ref_id,attr"`
			} `xml:"metadata>reference"`
			Root ovalCriteria `xml:"criteria"`
		}
		if err := d.DecodeElement(&def, &e); err != nil {
			return err
		}
		if def.Class != "vulnerability" || !strings.HasPrefix(def.ID, jammyOVALPrefix+"def:") {
			continue
		}
		cve := ""
		for _, ref := range def.Refs {
			if ref.Source == "CVE" && cveID.MatchString(ref.ID) {
				if cve != "" {
					cve = ""
					break
				}
				cve = ref.ID
			}
		}
		c := def.Root
		if cve == "" || !ovalPositive(c.Negate) || (c.Operator != "" && c.Operator != "AND") || len(c.Extends) != 1 ||
			c.Extends[0].Ref != jammyOVALPrefix+"def:100" || c.Extends[0].Applicability != "true" || !ovalPositive(c.Extends[0].Negate) {
			continue
		}
		checks := c.Checks
		if len(c.Groups) == 1 && len(checks) == 0 {
			g := c.Groups[0]
			if g.Operator != "OR" || !ovalPositive(g.Negate) || len(g.Extends) != 0 {
				continue
			}
			// Nested alternatives are ignored. A positive simple OR branch
			// is sufficient even when other branches have complex tests.
			checks = g.Checks
		} else if len(c.Groups) != 0 || len(checks) != 1 {
			continue
		}
		a := Advisory{ID: cve}
		for _, check := range checks {
			if ovalPositive(check.Negate) {
				names, fixed := packages.rule(check.Test)
				if len(names) > 0 {
					meta, _ := json.Marshal(map[string]string{"fixed": fixed})
					for _, name := range names {
						a.Affected = append(a.Affected, Affected{Ecosystem: compactdb.UbuntuJammyPackageOVAL, Name: name, EcosystemSpecific: meta})
					}
					continue
				}
			}
			pattern := states[tests[check.Test]]
			name, ok := strings.CutPrefix(check.Comment, "Is kernel '")
			name, ended := strings.CutSuffix(name, "' running?")
			if !ok || !ended || name == "" || !ovalPositive(check.Negate) || pattern == "" {
				continue
			}
			meta, _ := json.Marshal(map[string]string{"pattern": pattern})
			a.Affected = append(a.Affected, Affected{Ecosystem: compactdb.UbuntuJammyOVAL, Name: name, EcosystemSpecific: meta})
		}
		if len(a.Affected) == 0 {
			continue
		}
		count++
		if err := emit(a); err != nil {
			return err
		}
	}
	if count == 0 {
		return errors.New("Ubuntu OVAL contains no supported Jammy kernel definitions")
	}
	return nil
}

func readOVALUnameState(d *xml.Decoder, e xml.StartElement) (string, string, error) {
	var state struct {
		ID       string `xml:"id,attr"`
		Children []struct {
			XMLName xml.Name
			Attrs   []xml.Attr `xml:",any,attr"`
			Value   string     `xml:",chardata"`
		} `xml:",any"`
	}
	if err := d.DecodeElement(&state, &e); err != nil {
		return "", "", err
	}
	if len(state.Children) != 1 {
		return "", "", nil
	}
	c := state.Children[0]
	if c.XMLName != (xml.Name{Space: unameNamespace, Local: "os_release"}) || len(c.Attrs) != 1 || c.Attrs[0].Name.Local != "operation" || c.Attrs[0].Value != "pattern match" || len(c.Value) > 512 {
		return "", "", nil
	}
	if _, err := regexp.Compile("^(?:" + c.Value + ")$"); err != nil {
		return "", "", nil
	}
	return state.ID, c.Value, nil
}
