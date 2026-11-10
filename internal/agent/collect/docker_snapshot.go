package collect

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"shixpeer.com/ward/internal/atomicfile"
	"shixpeer.com/ward/pkg/inventory"
)

const DockerSnapshotFile = "docker-snapshot.json"

type dockerSnapshot struct {
	Version   int                         `json:"version"`
	At        time.Time                   `json:"collected_at"`
	Items     []inventory.Container       `json:"containers"`
	Firewall  []inventory.FirewallVerdict `json:"firewall,omitempty"`
	Listeners []inventory.Listener        `json:"listeners,omitempty"`
	Notes     []inventory.Note            `json:"coverage"`
}

func (h Host) CaptureDocker(ctx context.Context, out io.Writer) error {
	var snap inventory.Snapshot
	dockerCtx, stop := context.WithTimeout(ctx, 40*time.Second)
	h.collectDocker(dockerCtx, &snap)
	if dockerCtx.Err() != nil {
		snap.AddNote(inventory.Unavailable, "containers", "Docker capture exceeded its time budget")
	}
	stop()
	firewallCtx, finish := context.WithTimeout(ctx, 15*time.Second)
	h.firewall(firewallCtx, &snap)
	if firewallCtx.Err() != nil {
		snap.AddNote(inventory.Unavailable, "firewall", "automatic firewall capture exceeded its time budget")
	}
	finish()
	if err := ctx.Err(); err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(dockerSnapshot{Version: 1, At: time.Now().UTC(), Items: snap.Containers, Notes: snap.Coverage, Listeners: snap.Listeners, Firewall: snap.Firewall})
}

func (h Host) loadDockerSnapshot(s *inventory.Snapshot) bool {
	var doc dockerSnapshot
	if err := atomicfile.ReadJSON(h.DockerSnapshotPath, &doc, 16<<20); err != nil {
		return false
	}
	age := time.Since(doc.At)
	if doc.Version != 1 || age < -time.Minute || age > 15*time.Minute || len(doc.Items) > 1000 {
		s.AddNote(inventory.Unavailable, "containers", "Docker snapshot is stale or unsupported")
		return false
	}
	s.Containers = append(s.Containers, doc.Items...)
	s.Firewall = doc.Firewall
	type socket struct {
		family, protocol, address string
		port                      int
	}
	listeners := map[socket]int{}
	for i, l := range s.Listeners {
		listeners[socket{l.Family, l.Protocol, l.BindAddress, l.Port}] = i
	}
	for _, l := range doc.Listeners {
		key := socket{l.Family, l.Protocol, l.BindAddress, l.Port}
		if i, ok := listeners[key]; ok {
			if s.Listeners[i].PID == 0 && l.PID != 0 {
				s.Listeners[i].PID, s.Listeners[i].Process = l.PID, l.Process
			}
		} else {
			listeners[key] = len(s.Listeners)
			s.Listeners = append(s.Listeners, l)
		}
	}
	s.Coverage = append(s.Coverage, doc.Notes...)
	return true
}
