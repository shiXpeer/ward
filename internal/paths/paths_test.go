package paths

import (
	"path/filepath"
	"testing"
)

func TestHomeRootIgnoresLegacyXDGState(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", "/old/state")
	t.Setenv("XDG_CONFIG_HOME", "/old/config")
	if Root() != filepath.Join(home, ".shixpeer.ward") || State("agent") != filepath.Join(home, ".shixpeer.ward", "agent") || Config("agent") != filepath.Join(home, ".shixpeer.ward", "config", "agent.json") {
		t.Fatal(Root(), State("agent"), Config("agent"))
	}
}
