package collect

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"path"
	"strings"

	"shixpeer.com/ward/pkg/inventory"
)

func (h Host) dockerFile(ctx context.Context, socket, id, name string, limit int64) ([]byte, error) {
	out, err := h.commandLimit(ctx, int(limit)+4096, "docker", "--host", "unix://"+socket, "container", "cp", id+":"+name, "-")
	if err != nil {
		return nil, err
	}
	reader := tar.NewReader(bytes.NewReader(out))
	header, err := reader.Next()
	if err != nil || header.Typeflag != tar.TypeReg || header.Name != path.Base(name) || header.Size > limit {
		return nil, errors.New("unexpected container file archive")
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if _, err := reader.Next(); err != io.EOF {
		return nil, errors.New("unexpected additional container archive entries")
	}
	return data, nil
}

func (h Host) dockerPackages(ctx context.Context, socket string, c *inventory.Container) error {
	release, err := h.dockerFile(ctx, socket, c.ID, "/etc/os-release", 64<<10)
	if err != nil {
		release, err = h.dockerFile(ctx, socket, c.ID, "/usr/lib/os-release", 64<<10)
	}
	if err != nil {
		return err
	}
	c.Release = parseRelease(string(release), releaseKeys)
	if codename := inventory.UbuntuCodename(c.Release); codename != "" {
		c.Release["VERSION_CODENAME"] = codename
	}
	c.OS = c.Release["ID"]
	if c.OS != "ubuntu" && c.OS != "debian" {
		return errors.New("unsupported container distribution")
	}
	status, err := h.dockerFile(ctx, socket, c.ID, "/var/lib/dpkg/status", 4<<20)
	if err != nil {
		return err
	}
	c.Packages, err = parseDockerDPKG(string(status))
	return err
}

func parseDockerDPKG(status string) ([]inventory.Package, error) {
	var packages []inventory.Package
	for stanza := range strings.SplitSeq(status, "\n\n") {
		p := inventory.Package{Manager: "dpkg"}
		for line := range strings.SplitSeq(stanza, "\n") {
			key, value, ok := strings.Cut(line, ": ")
			if !ok {
				continue
			}
			switch key {
			case "Package":
				p.Name = value
			case "Version":
				p.Version = value
			case "Architecture":
				p.Architecture = value
			case "Status":
				p.Status = value
			case "Source":
				p.SourceName, p.SourceVersion, _ = strings.Cut(value, " (")
				p.SourceVersion = strings.TrimSuffix(p.SourceVersion, ")")
			}
		}
		if !strings.HasSuffix(p.Status, " ok installed") {
			continue
		}
		if p.Name == "" || p.Version == "" || len(packages) >= 10000 {
			return nil, errors.New("invalid or oversized dpkg status")
		}
		p.Status = "installed"
		packages = append(packages, p)
	}
	return packages, nil
}
