package main

import (
	"testing"

	"github.com/balyakin/agentwall/internal/config"
	"github.com/balyakin/agentwall/internal/ui"
)

func TestApplyFlagOverrides(t *testing.T) {
	cfg := config.Default()
	flags := &cliFlags{mode: "strict", port: 9999, noSanitize: true, failOnBlocked: true}
	if err := applyFlagOverrides(&cfg, flags); err != nil {
		t.Fatalf("applyFlagOverrides returned error: %v", err)
	}
	if cfg.Mode != "strict" || cfg.Port != 9999 {
		t.Fatalf("expected mode/port override")
	}
	if cfg.Sanitizers.Enabled {
		t.Fatalf("expected sanitizers disabled")
	}
	if !cfg.FailOnBlocked {
		t.Fatalf("expected fail_on_blocked enabled")
	}
}

func TestToHostCountersSorted(t *testing.T) {
	in := map[string]int{"b": 1, "a": 2}
	out := toHostCounters(in)
	if len(out) != 2 || out[0] != (ui.HostCounter{Host: "a", Count: 2}) {
		t.Fatalf("unexpected ordering: %+v", out)
	}
}

func TestReplayCommandArgsValidation(t *testing.T) {
	flags := &cliFlags{}
	cmd := newReplayCmd(flags)

	if err := cmd.Args(cmd, []string{"session.jsonl"}); err == nil {
		t.Fatalf("expected error when child command is missing")
	}
	if err := cmd.Args(cmd, []string{"session.jsonl", ""}); err == nil {
		t.Fatalf("expected error when child command is empty")
	}
	if err := cmd.Args(cmd, []string{"session.jsonl", "aider"}); err != nil {
		t.Fatalf("expected valid args, got: %v", err)
	}
}

func TestApplyFlagOverridesInvalidResponseModeFallsBack(t *testing.T) {
	cfg := config.Default()
	flags := &cliFlags{mode: "strict", responseSanitize: "unexpected"}
	if err := applyFlagOverrides(&cfg, flags); err != nil {
		t.Fatalf("applyFlagOverrides returned error: %v", err)
	}
	if cfg.ResponseSanitize.Mode != "block" {
		t.Fatalf("expected strict fallback mode 'block', got %s", cfg.ResponseSanitize.Mode)
	}
}
