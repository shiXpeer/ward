package source

import (
	"encoding/xml"
	"regexp"
	"strings"
)

const ovalLinuxNamespace = "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux"
const ovalDefinitionsNamespace = "http://oval.mitre.org/XMLSchema/oval-definitions-5"

var ovalBinaryName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)

type ovalEntity struct {
	XMLName xml.Name
	Attrs   []xml.Attr `xml:",any,attr"`
	Value   string     `xml:",chardata"`
}

type ovalPackageIndex struct {
	tests     map[string][2]string
	objects   map[string]ovalEntity
	states    map[string]string
	variables map[string][]string
}

func (p ovalPackageIndex) read(d *xml.Decoder, e xml.StartElement) error {
	switch {
	case e.Name.Space == ovalLinuxNamespace && e.Name.Local == "dpkginfo_test":
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
		if t.Check == "at least one" && t.Existence == "at_least_one_exists" && len(t.Objects) == 1 && len(t.States) == 1 {
			p.tests[t.ID] = [2]string{t.Objects[0].Ref, t.States[0].Ref}
		}
	case e.Name.Space == ovalLinuxNamespace && (e.Name.Local == "dpkginfo_object" || e.Name.Local == "dpkginfo_state"):
		var item struct {
			ID     string       `xml:"id,attr"`
			Fields []ovalEntity `xml:",any"`
		}
		if err := d.DecodeElement(&item, &e); err != nil {
			return err
		}
		if len(item.Fields) != 1 {
			return nil
		}
		field := item.Fields[0]
		if field.XMLName.Space != ovalLinuxNamespace {
			return nil
		}
		switch {
		case e.Name.Local == "dpkginfo_object" && field.XMLName.Local == "name":
			p.objects[item.ID] = field
		case e.Name.Local == "dpkginfo_state" && field.XMLName.Local == "evr" && len(field.Attrs) == 2 &&
			ovalAttr(field.Attrs, "operation") == "less than" && ovalAttr(field.Attrs, "datatype") == "debian_evr_string":
			p.states[item.ID] = strings.TrimSpace(field.Value)
		}
	case e.Name.Space == ovalDefinitionsNamespace && e.Name.Local == "constant_variable":
		var v struct {
			ID     string   `xml:"id,attr"`
			Type   string   `xml:"datatype,attr"`
			Values []string `xml:"value"`
		}
		if err := d.DecodeElement(&v, &e); err != nil {
			return err
		}
		if v.Type == "string" && len(v.Values) <= 128 {
			p.variables[v.ID] = v.Values
		}
	}
	return nil
}

func ovalAttr(attrs []xml.Attr, name string) string {
	for _, attr := range attrs {
		if attr.Name.Space == "" && attr.Name.Local == name {
			return attr.Value
		}
	}
	return ""
}

func (p ovalPackageIndex) rule(id string) ([]string, string) {
	refs := p.tests[id]
	fixed := p.states[refs[1]]
	if fixed == "" {
		return nil, ""
	}
	name := p.objects[refs[0]]
	if len(name.Attrs) == 0 && ovalBinaryName.MatchString(name.Value) {
		return []string{name.Value}, fixed
	}
	if len(name.Attrs) != 2 || ovalAttr(name.Attrs, "var_check") != "at least one" {
		return nil, ""
	}
	values := p.variables[ovalAttr(name.Attrs, "var_ref")]
	for _, v := range values {
		if !ovalBinaryName.MatchString(v) {
			return nil, ""
		}
	}
	return values, fixed
}
