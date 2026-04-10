package auditlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriterAndStats(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	w, err := NewWriter(path, 10, false, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	_ = w.Write(map[string]any{"action": "allow", "host": "api.openai.com"})
	_ = w.Write(map[string]any{"action": "block", "host": "statsig.anthropic.com"})
	_ = w.Write(map[string]any{"action": "clean", "host": "api.openai.com"})

	st, err := ComputeStats(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Allowed != 1 || st.Blocked != 1 || st.Sanitized != 1 {
		t.Fatalf("unexpected stats: %+v", st)
	}
}

func TestGrepAndTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.jsonl")
	if err := os.WriteFile(path, []byte("alpha\nbeta\ngamma\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var grepOut strings.Builder
	if err := Grep(path, "beta", func(line string) { grepOut.WriteString(line) }); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(grepOut.String(), "beta") {
		t.Fatalf("grep output missing expected line")
	}

	var tailOut strings.Builder
	if err := Tail(path, false, func(line string) { tailOut.WriteString(line) }); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(tailOut.String(), "gamma") {
		t.Fatalf("tail output missing expected content")
	}
}
