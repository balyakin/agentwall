package doctor

import (
	"path/filepath"
	"testing"

	"github.com/balyakin/agentwall/internal/config"
)

func TestDoctorReport(t *testing.T) {
	cfg := config.Default()
	cfg.Log.Path = filepath.Join(t.TempDir(), "log.jsonl")
	cfg.Port = 18729
	report := Run(cfg)
	if len(report.Checks) == 0 {
		t.Fatalf("expected checks")
	}
	if report.RenderText() == "" {
		t.Fatalf("expected text rendering")
	}
	if report.RenderJSON() == "" {
		t.Fatalf("expected json rendering")
	}
}
