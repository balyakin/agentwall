package replay

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestRecordLoadAndReplayTransport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.jsonl")
	r, err := NewRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	reqBody := []byte(`{"x":1}`)
	r.RecordRequest(http.MethodPost, "https://api.openai.com/v1/chat/completions", http.Header{"Content-Type": []string{"application/json"}}, reqBody)
	r.RecordResponse(http.MethodPost, "https://api.openai.com/v1/chat/completions", reqBody, 200, http.Header{"Content-Type": []string{"application/json"}}, []byte(`{"ok":true}`), nil)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	transport := &ReplayTransport{Player: p}
	req, _ := http.NewRequest(http.MethodPost, "https://api.openai.com/v1/chat/completions", io.NopCloser(bytes.NewReader(reqBody)))
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	if string(out) != `{"ok":true}` {
		t.Fatalf("unexpected replay body: %s", string(out))
	}
}

func TestLoadHandlesLargeJSONLEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.jsonl")
	large := bytes.Repeat([]byte("a"), 128*1024)
	entry := Entry{
		Kind:       "response",
		Key:        RequestKey(http.MethodPost, "https://api.openai.com/v1/chat/completions", []byte(`{"x":1}`)),
		Method:     http.MethodPost,
		URL:        "https://api.openai.com/v1/chat/completions",
		StatusCode: http.StatusOK,
		Headers:    http.Header{"Content-Type": []string{"application/json"}},
		Body:       large,
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	player, err := Load(path)
	if err != nil {
		t.Fatalf("expected load to support large JSONL entries: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://api.openai.com/v1/chat/completions", io.NopCloser(bytes.NewReader([]byte(`{"x":1}`))))
	if _, ok := player.FindResponse(req, []byte(`{"x":1}`)); !ok {
		t.Fatalf("expected large response entry to be available")
	}
}
