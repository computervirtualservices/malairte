package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── DefaultConfig ─────────────────────────────────────────────────────────────

func TestDefaultConfig_Fields(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Network != "mainnet" {
		t.Errorf("Network: got %q, want mainnet", cfg.Network)
	}
	if cfg.RPCAddr != "127.0.0.1:9332" {
		t.Errorf("RPCAddr: got %q, want 127.0.0.1:9332", cfg.RPCAddr)
	}
	if cfg.P2PAddr != "0.0.0.0:9333" {
		t.Errorf("P2PAddr: got %q, want 0.0.0.0:9333", cfg.P2PAddr)
	}
	if cfg.Mine {
		t.Error("Mine should default to false")
	}
	if cfg.MinerKey != "" {
		t.Errorf("MinerKey: got %q, want empty", cfg.MinerKey)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel: got %q, want info", cfg.LogLevel)
	}
	if cfg.MaxPeers != 125 {
		t.Errorf("MaxPeers: got %d, want 125", cfg.MaxPeers)
	}
	if cfg.MaxMempool != 300 {
		t.Errorf("MaxMempool: got %d, want 300", cfg.MaxMempool)
	}
	if cfg.DataDir == "" {
		t.Error("DataDir must not be empty")
	}
	if cfg.SeedPeers == nil {
		t.Error("SeedPeers must not be nil")
	}
}

func TestDefaultConfig_DataDirIsAbsolute(t *testing.T) {
	cfg := DefaultConfig()
	if !filepath.IsAbs(cfg.DataDir) {
		t.Errorf("DataDir %q should be an absolute path", cfg.DataDir)
	}
}

func TestDefaultConfig_DataDirContainsMalairted(t *testing.T) {
	cfg := DefaultConfig()
	// The default data dir should contain "malairted" or "Malairted"
	// regardless of OS (case-insensitive check).
	lower := strings.ToLower(cfg.DataDir)
	if !strings.Contains(lower, "malairted") {
		t.Errorf("DataDir %q should contain 'malairted'", cfg.DataDir)
	}
}

// ── defaultDataDir ────────────────────────────────────────────────────────────

func TestDefaultDataDir_NotEmpty(t *testing.T) {
	dir := defaultDataDir()
	if dir == "" {
		t.Error("defaultDataDir should not return an empty string")
	}
}

func TestDefaultDataDir_Absolute(t *testing.T) {
	dir := defaultDataDir()
	if !filepath.IsAbs(dir) {
		t.Errorf("defaultDataDir should return an absolute path, got %q", dir)
	}
}

// ── expandPath ────────────────────────────────────────────────────────────────

func TestExpandPath_Empty(t *testing.T) {
	if got := expandPath(""); got != "" {
		t.Errorf("expandPath(%q): got %q, want empty string", "", got)
	}
}

func TestExpandPath_NoSpecialChars(t *testing.T) {
	p := "/absolute/path/to/somewhere"
	if got := expandPath(p); got != p {
		t.Errorf("expandPath(%q): got %q, want unchanged", p, got)
	}
}

func TestExpandPath_Tilde(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home dir:", err)
	}
	got := expandPath("~/mydir")
	want := filepath.Join(home, "mydir")
	if got != want {
		t.Errorf("expandPath(~/mydir): got %q, want %q", got, want)
	}
}

func TestExpandPath_TildeOnly(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot determine home dir:", err)
	}
	got := expandPath("~")
	if got != home {
		t.Errorf("expandPath(~): got %q, want %q", got, home)
	}
}

func TestExpandPath_TildeNoSlash_Unchanged(t *testing.T) {
	// "~foo" (tilde without slash) should NOT be expanded — only "~" or "~/" are
	// recognized prefixes.
	p := "~foo/bar"
	got := expandPath(p)
	// os.ExpandEnv won't touch ~foo, and our code only replaces "~/" or exact "~".
	// The result must not accidentally prepend the home dir.
	home, _ := os.UserHomeDir()
	if strings.HasPrefix(got, home) {
		t.Errorf("expandPath(%q) should not expand ~foo as home dir, got %q", p, got)
	}
}

func TestExpandPath_EnvVar(t *testing.T) {
	t.Setenv("MALAIRT_TEST_VAR", "/injected/path")
	got := expandPath("$MALAIRT_TEST_VAR/sub")
	if !strings.HasPrefix(got, "/injected/path") {
		t.Errorf("expandPath with env var: got %q, expected prefix /injected/path", got)
	}
}

func TestExpandPath_EnvVar_Unset(t *testing.T) {
	// An unset env var expands to empty string by os.ExpandEnv.
	os.Unsetenv("MALAIRT_NONEXISTENT_VAR_XYZ")
	got := expandPath("$MALAIRT_NONEXISTENT_VAR_XYZ/foo")
	// os.ExpandEnv replaces unknown vars with ""; result should be "/foo"
	if got != "/foo" {
		t.Errorf("expandPath with unset var: got %q, want /foo", got)
	}
}
