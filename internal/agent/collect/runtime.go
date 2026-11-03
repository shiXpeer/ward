package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"shixpeer.com/ward/pkg/inventory"
)

const maxRuntime = 10000

func bindScope(host string) string {
	host = strings.Trim(host, "[]")
	if host == "*" || host == "0.0.0.0" || host == "::" || host == "" {
		return "wildcard"
	}
	ip := net.ParseIP(strings.Split(host, "%")[0])
	if ip == nil {
		return "unknown"
	}
	if ip.IsLoopback() {
		return "loopback"
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return "private"
	}
	return "public-address"
}
func endpoint(s string) (string, int, error) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", 0, fmt.Errorf("invalid socket endpoint")
	}
	p, e := strconv.Atoi(s[i+1:])
	if e != nil || p < 1 || p > 65535 {
		return "", 0, fmt.Errorf("invalid socket port")
	}
	return s[:i], p, nil
}
func (h Host) runtimeState(ctx context.Context, s *inventory.Snapshot) {
	keep := s.Coverage[:0]
	for _, n := range s.Coverage {
		if n.Source != "services" && n.Source != "listeners" && n.Source != "containers" {
			keep = append(keep, n)
		}
	}
	s.Coverage = keep
	if runtime.GOOS == "darwin" {
		out, e := h.commandLimit(ctx, 4<<20, "launchctl", "list")
		if e != nil {
			s.AddNote(inventory.Unavailable, "services", "launchctl list failed or exceeded limits")
		} else {
			parseLaunchctl(string(out), s)
		}
		for _, proto := range []string{"TCP", "UDP"} {
			args := []string{"-nP", "-i" + proto, "-FpcfPnt"}
			if proto == "TCP" {
				args = append(args, "-sTCP:LISTEN")
			}
			out, e = h.commandLimit(ctx, 4<<20, "lsof", args...)
			if e != nil {
				s.AddNote(inventory.Unavailable, "listeners-"+proto, "lsof did not return a complete socket inventory")
				continue
			}
			if e = parseLSOF(string(out), s); e != nil {
				s.AddNote(inventory.Truncated, "listeners", e.Error())
			}
		}
	} else if runtime.GOOS == "linux" {
		out, e := h.commandLimit(ctx, 4<<20, "systemctl", "list-units", "--type=service", "--all", "--no-pager", "--no-legend", "--plain")
		if e != nil {
			s.AddNote(inventory.Unavailable, "services", "systemctl inventory unavailable")
		} else {
			parseSystemctl(string(out), s)
		}
		out, e = h.commandLimit(ctx, 4<<20, "ss", "-H", "-lntup")
		if e != nil {
			if fallbackErr := procSockets(ctx, s); fallbackErr != nil {
				s.AddNote(inventory.Unavailable, "listeners", "ss and proc socket inventory unavailable or incomplete: "+fallbackErr.Error())
			}
		} else if e = parseSS(string(out), s); e != nil {
			s.AddNote(inventory.Unavailable, "listeners", e.Error())
		}
	} else {
		s.AddNote(inventory.NotChecked, "services", "unsupported runtime platform")
		s.AddNote(inventory.NotChecked, "listeners", "unsupported runtime platform")
	}
	servicePIDs := map[int]string{}
	for _, service := range s.Services {
		if service.PID > 0 {
			servicePIDs[service.PID] = service.Name
		}
	}
	for i := range s.Listeners {
		l := &s.Listeners[i]
		if name := servicePIDs[l.PID]; l.PID > 0 && name != "" {
			l.Service = name
		}
		if runtime.GOOS == "linux" && l.PID > 0 {
			f, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", l.PID))
			if err == nil {
				data, _ := io.ReadAll(io.LimitReader(f, 16384))
				f.Close()
				for _, part := range strings.FieldsFunc(string(data), func(r rune) bool { return r == '/' || r == '\n' }) {
					if strings.HasSuffix(part, ".service") {
						l.SystemdUnit = part
						l.Service = part
					}
				}
			}
		}
	}
	s.AddNote(inventory.NotChecked, "process-scope", "service registry and socket owners are collected; a complete process/command-line inventory is deliberately not read")
	s.AddNote(inventory.Unresolved, "reachability", "socket bindings are local evidence only; NAT, firewall, cloud rules and external reachability are not tested; unprivileged process visibility may be limited")
	h.containers(ctx, s)
}
func parseLaunchctl(text string, s *inventory.Snapshot) {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || f[0] == "PID" {
			continue
		}
		if len(s.Services) >= maxRuntime {
			s.AddNote(inventory.Truncated, "services", "service limit reached")
			return
		}
		active := "loaded"
		if f[0] != "-" {
			active = "running"
		}
		pid, _ := strconv.Atoi(f[0])
		s.Services = append(s.Services, inventory.Service{Name: f[2], Active: active, State: f[1], PID: pid})
	}
}
func parseSystemctl(text string, s *inventory.Snapshot) {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || !strings.HasSuffix(f[0], ".service") {
			continue
		}
		if len(s.Services) >= maxRuntime {
			s.AddNote(inventory.Truncated, "services", "service limit reached")
			return
		}
		s.Services = append(s.Services, inventory.Service{Name: f[0], Active: f[2], State: f[3]})
	}
}
func parseLSOF(text string, s *inventory.Snapshot) error {
	pid := 0
	process := ""
	proto := ""
	family := ""
	for _, line := range strings.Split(text, "\n") {
		if len(line) < 2 {
			continue
		}
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(line[1:])
			process = ""
			proto = ""
			family = ""
		case 'c':
			process = line[1:]
		case 'f':
			proto = ""
			family = ""
		case 'P':
			proto = strings.ToLower(line[1:])
		case 't':
			family = line[1:]
		case 'n':
			addr := line[1:]
			if strings.Contains(addr, "->") {
				continue
			}
			host, port, e := endpoint(addr)
			if e != nil {
				continue
			}
			if proto != "tcp" && proto != "udp" {
				continue
			}
			if len(s.Listeners) >= maxRuntime {
				return fmt.Errorf("socket limit reached")
			}
			s.Listeners = append(s.Listeners, inventory.Listener{Family: family, Protocol: proto, Port: port, BindScope: bindScope(host), Process: process, PID: pid, Evidence: "lsof", Reachability: "UNKNOWN"})
		}
	}
	return nil
}

var ssProcess = regexp.MustCompile(`"([^"\n]{1,256})",pid=([0-9]+)`)

func parseSS(text string, s *inventory.Snapshot) error {
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 {
			if strings.TrimSpace(line) != "" {
				return fmt.Errorf("unrecognized ss output")
			}
			continue
		}
		if f[0] != "tcp" && f[0] != "udp" {
			continue
		}
		host, port, e := endpoint(f[4])
		if e != nil {
			continue
		}
		family := "IPv4"
		if strings.Contains(host, ":") {
			family = "IPv6"
		}
		l := inventory.Listener{Family: family, Protocol: f[0], Port: port, BindScope: bindScope(host), Evidence: "ss", Reachability: "UNKNOWN"}
		if m := ssProcess.FindStringSubmatch(strings.Join(f[6:], " ")); len(m) > 0 {
			l.Process = m[1]
			l.PID, _ = strconv.Atoi(m[2])
		}
		if len(s.Listeners) >= maxRuntime {
			return fmt.Errorf("socket limit reached")
		}
		s.Listeners = append(s.Listeners, l)
	}
	return nil
}
func (h Host) containers(ctx context.Context, s *inventory.Snapshot) {
	sockets := []string{"/var/run/docker.sock"}
	if home, e := os.UserHomeDir(); e == nil {
		sockets = append(sockets, filepath.Join(home, ".docker", "run", "docker.sock"))
	}
	socket := ""
	for _, path := range sockets {
		if st, e := os.Stat(path); e == nil && st.Mode()&os.ModeSocket != 0 {
			socket = path
			break
		}
	}
	if socket == "" {
		s.AddNote(inventory.Unavailable, "containers", "no supported local Docker socket found; remote contexts are not contacted")
		return
	}
	h.docker(ctx, s, socket)
}
func (h Host) docker(ctx context.Context, s *inventory.Snapshot, socket string) {
	prefix := []string{"--host", "unix://" + socket}
	args := append(append([]string{}, prefix...), "container", "ls", "--quiet", "--no-trunc")
	out, e := h.commandLimit(ctx, 1<<20, "docker", args...)
	if e != nil {
		s.AddNote(inventory.Unavailable, "containers", "local Docker listing unavailable; no privilege escalation attempted")
		return
	}
	ids := strings.Fields(string(out))
	if len(ids) > 1000 {
		s.AddNote(inventory.Truncated, "containers", "container limit reached")
		ids = ids[:1000]
	}
	const format = `{"name":{{json .Name}},"image":{{json .Config.Image}},"image_id":{{json .Image}},"started_at":{{json .State.StartedAt}},"ports":{{json .NetworkSettings.Ports}}}`
	for start := 0; start < len(ids); start += 32 {
		end := start + 32
		if end > len(ids) {
			end = len(ids)
		}
		for _, id := range ids[start:end] {
			if len(id) != 64 || strings.Trim(id, "0123456789abcdef") != "" {
				s.AddNote(inventory.Unavailable, "containers", "invalid Docker container identity")
				return
			}
		}
		args = append(append([]string{}, prefix...), "container", "inspect", "--format", format)
		args = append(args, ids[start:end]...)
		out, e = h.commandLimit(ctx, 4<<20, "docker", args...)
		if e != nil {
			s.AddNote(inventory.Unavailable, "containers", "container inspection failed (possibly stopped during collection)")
			continue
		}
		if e = parseDocker(string(out), s); e != nil {
			s.AddNote(inventory.Unavailable, "containers", "invalid container metadata")
		}
	}
	s.AddNote(inventory.NotChecked, "container-packages", "container images/ports are inventoried; packages inside containers are not inspected and image tags are not used as package versions")
}
func parseDocker(text string, s *inventory.Snapshot) error {
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		if line == "" {
			continue
		}
		var r struct {
			Name    string                                         `json:"name"`
			Image   string                                         `json:"image"`
			ImageID string                                         `json:"image_id"`
			Started string                                         `json:"started_at"`
			Ports   map[string][]struct{ HostIP, HostPort string } `json:"ports"`
		}
		if e := json.Unmarshal([]byte(line), &r); e != nil {
			return e
		}
		c := inventory.Container{Name: strings.TrimPrefix(r.Name, "/"), Image: r.Image, ImageID: r.ImageID, StartedAt: r.Started}
		for key, bindings := range r.Ports {
			dest, proto, ok := strings.Cut(key, "/")
			if !ok {
				continue
			}
			for _, p := range bindings {
				port, e := strconv.Atoi(p.HostPort)
				if e != nil || port < 1 || port > 65535 {
					continue
				}
				family := "IPv4"
				if strings.Contains(p.HostIP, ":") {
					family = "IPv6"
				}
				c.Ports = append(c.Ports, inventory.PublishedPort{Family: family, Protocol: proto, HostPort: port, ContainerPort: dest, BindScope: bindScope(p.HostIP), Evidence: "docker-inspect", Reachability: "UNKNOWN"})
			}
		}
		s.Containers = append(s.Containers, c)
	}
	return nil
}
