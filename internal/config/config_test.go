package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMergesGlobalAndProjectAndEnv(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	appDir := filepath.Join(home, ".agentwall")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	global := []byte("mode: loose\nport: 9000\n")
	if err := os.WriteFile(filepath.Join(appDir, "config.yaml"), global, 0o600); err != nil {
		t.Fatal(err)
	}

	project := t.TempDir()
	if err := os.WriteFile(filepath.Join(project, ".agentwall.yaml"), []byte("mode: strict\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prev, _ := os.Getwd()
	defer func() { _ = os.Chdir(prev) }()
	if err := os.Chdir(project); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTWALL_PORT", "7777")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "strict" {
		t.Fatalf("expected project mode override, got %s", cfg.Mode)
	}
	if cfg.Port != 7777 {
		t.Fatalf("expected env port override, got %d", cfg.Port)
	}
}

func TestFindProjectConfig(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(child, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, ".agentwall.yaml")
	if err := os.WriteFile(marker, []byte("mode: balanced\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	found, err := FindProjectConfig(child)
	if err != nil {
		t.Fatal(err)
	}
	if found != marker {
		t.Fatalf("expected %s, got %s", marker, found)
	}
}

func TestLoadKeepsDefaultBoolWhenNotSpecified(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	appDir := filepath.Join(home, ".agentwall")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "config.yaml"), []byte("mode: strict\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	project := t.TempDir()
	prev, _ := os.Getwd()
	defer func() { _ = os.Chdir(prev) }()
	if err := os.Chdir(project); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Sanitizers.Enabled {
		t.Fatalf("expected sanitizers.enabled to keep default true")
	}
	if !cfg.EnvGuard.Enabled {
		t.Fatalf("expected env_guard.enabled to keep default true")
	}
	if cfg.ResponseSanitize.Mode != "block" {
		t.Fatalf("expected strict default response mode block, got %s", cfg.ResponseSanitize.Mode)
	}
}

func TestLoadAppliesExplicitFalseBoolOverride(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	appDir := filepath.Join(home, ".agentwall")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	configYAML := []byte("sanitizers:\n  enabled: false\nenv_guard:\n  enabled: false\n")
	if err := os.WriteFile(filepath.Join(appDir, "config.yaml"), configYAML, 0o600); err != nil {
		t.Fatal(err)
	}

	project := t.TempDir()
	prev, _ := os.Getwd()
	defer func() { _ = os.Chdir(prev) }()
	if err := os.Chdir(project); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sanitizers.Enabled {
		t.Fatalf("expected sanitizers.enabled false from config")
	}
	if cfg.EnvGuard.Enabled {
		t.Fatalf("expected env_guard.enabled false from config")
	}
}

func TestLoadExpandsUserPath(t *testing.T) {
	home := t.TempDir()
	setTestHome(t, home)
	appDir := filepath.Join(home, ".agentwall")
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "config.yaml"), []byte("log:\n  path: ~/.agentwall/custom-log.jsonl\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	project := t.TempDir()
	prev, _ := os.Getwd()
	defer func() { _ = os.Chdir(prev) }()
	if err := os.Chdir(project); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".agentwall", "custom-log.jsonl")
	if cfg.Log.Path != want {
		t.Fatalf("expected expanded path %s, got %s", want, cfg.Log.Path)
	}
}

func setTestHome(t *testing.T, home string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOMEDRIVE", "")
	t.Setenv("HOMEPATH", home)
}
