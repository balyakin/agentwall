package sanitize

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestRedactBuiltinPattern(t *testing.T) {
	s, err := New(Config{Enabled: true, MaxBodyBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`token=sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG`)
	out, ids := s.RedactBytes(body, false)
	if string(out) == string(body) {
		t.Fatalf("expected body to be sanitized")
	}
	if len(ids) == 0 {
		t.Fatalf("expected sanitizer id")
	}
}

func TestAuthorizationHeaderUntouched(t *testing.T) {
	s, err := New(Config{Enabled: true, MaxBodyBytes: 1024})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, "https://api.openai.com/v1/chat/completions", io.NopCloser(strings.NewReader(`{"input":"sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"}`)))
	req.Header.Set("Authorization", "Bearer sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG")
	req.Header.Set("X-Trace", "Bearer sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG")
	req.Header.Set("Content-Type", "application/json")
	res, err := s.SanitizeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Authorization") == "Bearer ***REDACTED:BEARER***" {
		t.Fatalf("authorization header must not be changed")
	}
	if len(res.Applied) == 0 {
		t.Fatalf("expected redaction to occur in body or non-auth headers")
	}
}

func TestGzipSanitization(t *testing.T) {
	s, err := New(Config{Enabled: true, MaxBodyBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte(`{"prompt":"AKIA0123456789ABCDEF"}`)
	var gz bytes.Buffer
	gw := gzip.NewWriter(&gz)
	if _, err := gw.Write(plain); err != nil {
		t.Fatal(err)
	}
	_ = gw.Close()

	req, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", io.NopCloser(bytes.NewReader(gz.Bytes())))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Content-Length", "0")

	if _, err := s.SanitizeRequest(req); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	gr, err := gzip.NewReader(bytes.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	decoded, _ := io.ReadAll(gr)
	_ = gr.Close()
	if bytes.Contains(decoded, []byte("AKIA0123456789ABCDEF")) {
		t.Fatalf("expected gzip payload to be sanitized")
	}
}

func TestEnvSecretRedaction(t *testing.T) {
	s, err := New(Config{Enabled: true, MaxBodyBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	s.SetEnvSecrets(map[string]string{"MY_TOKEN": "super_secret_token_value"})
	out, ids := s.RedactBytes([]byte("token=super_secret_token_value"), false)
	if bytes.Contains(out, []byte("super_secret_token_value")) {
		t.Fatalf("expected env secret to be redacted")
	}
	found := false
	for _, id := range ids {
		if id == "env:MY_TOKEN" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected env sanitizer id")
	}
}

func TestSanitizeRequestDoesNotPanicOnSizeChange(t *testing.T) {
	s, err := New(Config{Enabled: true, MaxBodyBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"prompt":"bearer abcdefghijklmnopqrstuvwxyz123456"}`
	req, _ := http.NewRequest(http.MethodPost, "https://api.anthropic.com/v1/messages", io.NopCloser(strings.NewReader(body)))
	req.Header.Set("Content-Type", "application/json")
	if _, err := s.SanitizeRequest(req); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("bearer abcdefghijklmnopqrstuvwxyz123456")) {
		t.Fatalf("expected bearer token to be redacted")
	}
}

func TestWalkJSONArrayStringSelective(t *testing.T) {
	s, err := New(Config{Enabled: true, MaxBodyBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"tools":["sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"],"messages":[{"content":["sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"]}]}`)
	out, ids := s.sanitizeTrustedJSON(payload)
	if len(ids) == 0 {
		t.Fatalf("expected at least one sanitizer id")
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("sanitized payload must remain valid json: %v", err)
	}
	tools := decoded["tools"].([]any)
	if tools[0] != "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG" {
		t.Fatalf("strings in non-text arrays should not be mutated")
	}
	messages := decoded["messages"].([]any)
	message := messages[0].(map[string]any)
	content := message["content"].([]any)
	if strings.Contains(content[0].(string), "sk-proj-") {
		t.Fatalf("content array strings should be sanitized")
	}
}

func TestAWSSecretReplacementPreservesJSONShape(t *testing.T) {
	s, err := New(Config{Enabled: true, MaxBodyBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"aws_secret_key":"ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD"}`)
	out, ids := s.RedactBytes(raw, false)
	if len(ids) == 0 {
		t.Fatalf("expected aws secret sanitizer to apply")
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("replacement must keep valid JSON: %v", err)
	}
	if !strings.Contains(decoded["aws_secret_key"].(string), "***REDACTED") {
		t.Fatalf("expected aws secret value to be redacted")
	}
}
