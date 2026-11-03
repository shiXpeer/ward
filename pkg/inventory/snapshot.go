// Package inventory is the host observation written by hostagent.
// A snapshot records software state and versions. It does not decide whether
// a vulnerability applies, and a listener is not proof of reachability from
// the internet. Sections that were not inspected are listed in Coverage and
// omitted from the payload.
package inventory

import (
	"fmt"
	"time"
)

const FormatVersion = 1

const (
	Unavailable = "UNAVAILABLE"
	NotChecked  = "NOT_CHECKED"
	Truncated   = "TRUNCATED"
	Unresolved  = "UNRESOLVED"
)

// Snapshot is one collection pass. Coverage is always present; an empty
// package list is not evidence that the host has no packages.
type Snapshot struct {
	RunningKernel    *Kernel       `json:"running_kernel,omitempty"`
	FormatVersion    int           `json:"format_version"`
	Collector        string        `json:"collector"`
	CollectorVersion string        `json:"collector_version"`
	CollectedAt      time.Time     `json:"collected_at"`
	Host             Host          `json:"host"`
	Packages         []Package     `json:"packages,omitempty"`
	Services         []Service     `json:"services,omitempty"`
	Processes        []string      `json:"processes,omitempty"`
	Listeners        []Listener    `json:"listeners,omitempty"`
	Applications     []Application `json:"applications,omitempty"`
	Containers       []Container   `json:"containers,omitempty"`
	Dependencies     []Dependency  `json:"dependencies,omitempty"`
	Coverage         []Note        `json:"coverage"`
}

// Host is identity that is useful for version matching. It has no hostname.
type Host struct {
	OS           string            `json:"os,omitempty"`
	Uname        string            `json:"uname,omitempty"`
	Architecture string            `json:"architecture,omitempty"`
	Release      map[string]string `json:"release,omitempty"`
	UIDClass     string            `json:"uid_class,omitempty"`
}

type Package struct {
	UpstreamVersion string `json:"upstream_version,omitempty"`
	Provenance      string `json:"provenance,omitempty"`
	Manager         string `json:"manager"`
	Name            string `json:"name"`
	Version         string `json:"version"`
	Architecture    string `json:"architecture,omitempty"`
	SourceName      string `json:"source_name,omitempty"`
	SourceVersion   string `json:"source_version,omitempty"`
	Status          string `json:"status,omitempty"`
}

type Service struct {
	PID     int    `json:"pid,omitempty"`
	Name    string `json:"name"`
	Active  string `json:"active,omitempty"`
	State   string `json:"state,omitempty"`
	Enabled string `json:"enabled,omitempty"`
}

type Listener struct {
	Service      string `json:"service,omitempty"`
	Family       string `json:"family"`
	Protocol     string `json:"protocol"`
	Port         int    `json:"port"`
	BindScope    string `json:"bind_scope"`
	Process      string `json:"process,omitempty"`
	PID          int    `json:"pid,omitempty"`
	SystemdUnit  string `json:"systemd_unit,omitempty"`
	Evidence     string `json:"evidence,omitempty"`
	Reachability string `json:"reachability,omitempty"`
}

type Application struct {
	VersionKind string `json:"version_kind,omitempty"`
	Identifier  string `json:"identifier,omitempty"`
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
}

type Container struct {
	Name         string          `json:"name"`
	Image        string          `json:"image,omitempty"`
	ImageID      string          `json:"image_id,omitempty"`
	Digest       string          `json:"digest,omitempty"`
	OS           string          `json:"os,omitempty"`
	Architecture string          `json:"architecture,omitempty"`
	StartedAt    string          `json:"started_at,omitempty"`
	Packages     []Package       `json:"packages,omitempty"`
	Applications []Application   `json:"applications,omitempty"`
	Ports        []PublishedPort `json:"ports,omitempty"`
}

type PublishedPort struct {
	Family        string `json:"family"`
	Protocol      string `json:"protocol"`
	HostPort      int    `json:"host_port,omitempty"`
	BindScope     string `json:"bind_scope"`
	ContainerPort string `json:"container_port,omitempty"`
	Evidence      string `json:"evidence,omitempty"`
	Reachability  string `json:"reachability,omitempty"`
}

type Dependency struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

type Note struct {
	Code   string `json:"code"`
	Source string `json:"source"`
	Detail string `json:"detail"`
}

func (s *Snapshot) AddNote(code, source, detail string) {
	s.Coverage = append(s.Coverage, Note{Code: code, Source: source, Detail: detail})
}

func (s Snapshot) Validate() error {
	if s.FormatVersion != FormatVersion {
		return fmt.Errorf("inventory: format version %d, want %d", s.FormatVersion, FormatVersion)
	}
	if s.Collector == "" {
		return fmt.Errorf("inventory: collector is required")
	}
	if s.CollectedAt.IsZero() {
		return fmt.Errorf("inventory: collected_at is required")
	}
	if s.Coverage == nil {
		return fmt.Errorf("inventory: coverage must be present")
	}
	return nil
}

// Kernel separates the loaded source version from installed image package metadata.
type Kernel struct {
	Release                string `json:"release"`
	Package                string `json:"package,omitempty"`
	SourceName             string `json:"source_name,omitempty"`
	SourceVersion          string `json:"running_source_version,omitempty"`
	InstalledSourceVersion string `json:"installed_source_version,omitempty"`
	Status                 string `json:"status"`
	RebootRequired         bool   `json:"reboot_required"`
	Detail                 string `json:"detail,omitempty"`
}
