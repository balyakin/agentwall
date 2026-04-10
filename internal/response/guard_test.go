package response

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/balyakin/agentwall/internal/sanitize"
)

func newResp(body string) *http.Response {
	req, _ := http.NewRequest(http.MethodGet, "https://api.openai.com/v1/chat/completions", nil)
	return &http.Response{
		StatusCode:    http.StatusOK,
		Body:          io.NopCloser(bytes.NewReader([]byte(body))),
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Request:       req,
		ContentLength: int64(len(body)),
	}
}

func TestGuardModes(t *testing.T) {
	s, err := sanitize.New(sanitize.Config{Enabled: true, MaxBodyBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	secretBody := `{"output":"sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"}`

	detect := New("detect", s)
	resp, result, err := detect.Handle(newResp(secretBody))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(result.Applied) == 0 {
		t.Fatalf("detect mode should report applied ids")
	}
	if !bytes.Contains(body, []byte("sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG")) {
		t.Fatalf("detect mode must not mutate body")
	}

	sanitizeMode := New("sanitize", s)
	resp, result, err = sanitizeMode.Handle(newResp(secretBody))
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	if len(result.Applied) == 0 {
		t.Fatalf("sanitize mode should report ids")
	}
	if bytes.Contains(body, []byte("sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG")) {
		t.Fatalf("sanitize mode must mutate body")
	}

	block := New("block", s)
	resp, result, err = block.Handle(newResp(secretBody))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Blocked {
		t.Fatalf("block mode should block response")
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected forbidden from block mode")
	}

	lowConfidenceBody := `{"output":"Bearer abcdefghijklmnopqrstuvwxyz123456"}`
	resp, result, err = block.Handle(newResp(lowConfidenceBody))
	if err != nil {
		t.Fatal(err)
	}
	if result.Blocked {
		t.Fatalf("block mode should sanitize low-confidence secrets, not block")
	}
	body, _ = io.ReadAll(resp.Body)
	if bytes.Contains(body, []byte("Bearer abcdefghijklmnopqrstuvwxyz123456")) {
		t.Fatalf("expected low-confidence secret to be sanitized in strict mode")
	}
}

func TestGuardHandlesCompressedResponses(t *testing.T) {
	s, err := sanitize.New(sanitize.Config{Enabled: true, MaxBodyBytes: 1024 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	g := New("sanitize", s)

	plain := []byte(`{"output":"sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"}`)
	var compressed bytes.Buffer
	gw := gzip.NewWriter(&compressed)
	if _, err := gw.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet, "https://api.openai.com/v1/chat/completions", nil)
	resp := &http.Response{
		StatusCode:    http.StatusOK,
		Body:          io.NopCloser(bytes.NewReader(compressed.Bytes())),
		Header:        http.Header{"Content-Type": []string{"application/json"}, "Content-Encoding": []string{"gzip"}},
		Request:       req,
		ContentLength: int64(compressed.Len()),
	}

	outResp, result, err := g.Handle(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Applied) == 0 {
		t.Fatalf("expected sanitizer ids for compressed response")
	}
	encoded, err := io.ReadAll(outResp.Body)
	if err != nil {
		t.Fatal(err)
	}
	gr, err := gzip.NewReader(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(gr)
	if err != nil {
		t.Fatal(err)
	}
	_ = gr.Close()
	if bytes.Contains(decoded, []byte("sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG")) {
		t.Fatalf("expected secret to be redacted in compressed response")
	}
}

func TestGuardStreamingObserverBlock(t *testing.T) {
	s, err := sanitize.New(sanitize.Config{Enabled: true, MaxBodyBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	g := New("block", s)
	ch := make(chan Result, 1)
	g.SetStreamObserver(func(req *http.Request, result Result) {
		ch <- result
	})

	req, _ := http.NewRequest(http.MethodGet, "https://api.openai.com/v1/chat/completions", nil)
	body := "data: {\"delta\":\"sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG\"}\n\n"
	resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: io.NopCloser(bytes.NewReader([]byte(body))), Request: req}

	outResp, result, err := g.Handle(resp)
	if err != nil {
		t.Fatal(err)
	}
	if result.Blocked {
		t.Fatalf("streaming handle should report via observer, not immediate result")
	}
	all, err := io.ReadAll(outResp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(all, []byte("blocked by agentwall")) {
		t.Fatalf("expected blocked stream payload")
	}

	select {
	case observed := <-ch:
		if !observed.Blocked {
			t.Fatalf("expected blocked observation")
		}
		if len(observed.Applied) == 0 {
			t.Fatalf("expected applied sanitizer ids in observation")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for stream observer")
	}
}
