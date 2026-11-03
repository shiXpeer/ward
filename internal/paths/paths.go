// Package paths keeps Ward runtime data under the executing account's home.
package paths

import (
	"os"
	"path/filepath"
	"runtime"
)

func Root() string {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return ""
	}
	return filepath.Join(home, ".shixpeer.ward")
}
func State(component string) string  { return filepath.Join(Root(), component) }
func Config(component string) string { return filepath.Join(Root(), "config", component+".json") }

// LegacyConfig is only used by the explicit, non-destructive migration command.
func LegacyConfig() string {
	if os.Geteuid() == 0 {
		return "/etc/shixpeer-ward/agent.json"
	}
	if runtime.GOOS == "darwin" {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, "Library", "Application Support", "shixpeer-ward", "agent.json")
	}
	base, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(base, "shixpeer-ward", "agent.json")
}
