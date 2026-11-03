package collect

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"shixpeer.com/ward/pkg/inventory"
)

var errDependencyLimit = errors.New("invalid or excessive dependency metadata")

func (h Host) globalDependencies(ctx context.Context, s *inventory.Snapshot) {
	keep := s.Coverage[:0]
	for _, n := range s.Coverage {
		if n.Source != "dependencies" {
			keep = append(keep, n)
		}
	}
	s.Coverage = keep
	// -I -S prevents user startup hooks, PYTHONPATH and .pth execution. Metadata
	// is read directly from this interpreter's global sysconfig paths.
	const script = `import importlib.metadata as m,json,sysconfig; paths=sorted(set(sysconfig.get_path(k) for k in ('purelib','platlib'))); print(json.dumps([{'name':d.metadata.get('Name',''),'version':d.version} for d in m.distributions(path=paths)]))`
	out, e := h.commandLimit(ctx, 4<<20, "python3", "-I", "-S", "-c", script)
	if e != nil {
		s.AddNote(inventory.Unavailable, "python-global", "isolated global Python metadata probe unavailable")
	} else if e = parsePython(out, s); e != nil {
		s.AddNote(inventory.Unavailable, "python-global", "invalid or excessive Python metadata")
	}
	out, e = h.commandLimit(ctx, 4<<20, "npm", "ls", "--global", "--depth=0", "--json", "--ignore-scripts", "--offline", "--no-audit", "--no-fund", "--loglevel=error")
	if e != nil {
		s.AddNote(inventory.Unavailable, "npm-global", "offline global npm inventory unavailable")
	} else if e = parseNPM(out, s); e != nil {
		s.AddNote(inventory.Unavailable, "npm-global", "invalid or excessive npm inventory")
	}
	s.AddNote(inventory.NotChecked, "dependency-scope", "only current interpreter global Python metadata and global top-level npm packages are inspected; virtual environments, project lockfiles, nested dependencies and other runtimes are not scanned")
}
func parsePython(raw []byte, s *inventory.Snapshot) error {
	var rows []struct{ Name, Version string }
	if e := json.Unmarshal(raw, &rows); e != nil {
		return e
	}
	if len(rows) > maxRuntime {
		return errDependencyLimit
	}
	for _, p := range rows {
		if p.Name == "" || p.Version == "" || len(p.Name) > 512 || len(p.Version) > 512 {
			continue
		}
		name := strings.ToLower(p.Name)
		name = strings.NewReplacer("_", "-", ".", "-").Replace(name)
		for strings.Contains(name, "--") {
			name = strings.ReplaceAll(name, "--", "-")
		}
		s.Dependencies = append(s.Dependencies, inventory.Dependency{Ecosystem: "PyPI", Name: name, Version: p.Version})
	}
	return nil
}
func parseNPM(raw []byte, s *inventory.Snapshot) error {
	var r struct {
		Dependencies map[string]struct{ Version string }
		Error        json.RawMessage
		Problems     []string
	}
	if e := json.Unmarshal(raw, &r); e != nil {
		return e
	}
	if len(r.Error) > 0 || len(r.Problems) > 0 {
		return errDependencyLimit
	}
	if len(r.Dependencies) > maxRuntime {
		return errDependencyLimit
	}
	for name, p := range r.Dependencies {
		if name != "" && p.Version != "" && len(name) <= 512 && len(p.Version) <= 512 {
			s.Dependencies = append(s.Dependencies, inventory.Dependency{Ecosystem: "npm", Name: name, Version: p.Version})
		}
	}
	return nil
}
