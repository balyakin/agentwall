package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/balyakin/agentwall/internal/budget"
	"github.com/balyakin/agentwall/internal/ca"
	auditlog "github.com/balyakin/agentwall/internal/log"
	"github.com/balyakin/agentwall/internal/replay"
	"github.com/balyakin/agentwall/internal/response"
	"github.com/balyakin/agentwall/internal/rules"
	"github.com/balyakin/agentwall/internal/sanitize"
	"github.com/balyakin/agentwall/internal/ui"
)

type staticReadCloser struct{ io.Reader }

func (s staticReadCloser) Close() error { return nil }

func TestProxyBlocksTelemetryHost(t *testing.T) {
	eng, err := rules.New("balanced", nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := sanitize.New(sanitize.Config{Enabled: true, MaxBodyBytes: 1024 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	manager := ca.New(t.TempDir())
	if err := manager.Ensure(); err != nil {
		t.Fatal(err)
	}
	cert, err := manager.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}

	logWriter, err := auditlog.NewWriter(t.TempDir()+"/log.jsonl", 10, false, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer logWriter.Close()

	server, err := New(Options{
		Addr:      "127.0.0.1:18723",
		Mode:      "balanced",
		CACert:    cert,
		Engine:    eng,
		Sanitizer: s,
		Guard:     response.New("detect", s),
		Budget:    budget.New(0, "block"),
		UI:        ui.NewInline(io.Discard, true, false, true),
		Log:       logWriter,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := server.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer stopCancel()
		_ = server.Stop(stopCtx)
	})

	proxyURL, _ := url.Parse("http://127.0.0.1:18723")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := client.Get("http://statsig.anthropic.com/v1/rgstr")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for blocked telemetry, got %d", resp.StatusCode)
	}
}

func TestProxySanitizesRequestBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("secret leaked"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}))
	defer upstream.Close()

	eng, err := rules.New("balanced", nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := sanitize.New(sanitize.Config{Enabled: true, MaxBodyBytes: 1024 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	manager := ca.New(t.TempDir())
	if err := manager.Ensure(); err != nil {
		t.Fatal(err)
	}
	cert, err := manager.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}

	logWriter, err := auditlog.NewWriter(t.TempDir()+"/log.jsonl", 10, false, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer logWriter.Close()

	server, err := New(Options{
		Addr:      "127.0.0.1:18724",
		Mode:      "balanced",
		CACert:    cert,
		Engine:    eng,
		Sanitizer: s,
		Guard:     response.New("detect", s),
		UI:        ui.NewInline(io.Discard, true, false, true),
		Log:       logWriter,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := server.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer stopCancel()
		_ = server.Stop(stopCtx)
	})

	proxyURL, _ := url.Parse("http://127.0.0.1:18724")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	body := strings.NewReader(`{"prompt":"sk-proj-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"}`)
	req, _ := http.NewRequest(http.MethodPost, upstream.URL+"/echo", body)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from upstream after sanitization, got %d", resp.StatusCode)
	}
}

func TestTransportDoesNotUseParentProxyEnvByDefault(t *testing.T) {
	manager := ca.New(t.TempDir())
	if err := manager.Ensure(); err != nil {
		t.Fatal(err)
	}
	cert, err := manager.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Options{Mode: "balanced", CACert: cert})
	if err != nil {
		t.Fatal(err)
	}
	if server.proxy == nil || server.proxy.Tr == nil {
		t.Fatalf("expected proxy transport to be initialized")
	}
	if server.proxy.Tr.Proxy != nil {
		t.Fatalf("expected no inherited parent proxy in transport")
	}
}

func TestTransportUsesConfiguredUpstreamProxy(t *testing.T) {
	manager := ca.New(t.TempDir())
	if err := manager.Ensure(); err != nil {
		t.Fatal(err)
	}
	cert, err := manager.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Options{Mode: "balanced", CACert: cert, UpstreamProxy: "http://127.0.0.1:19001"})
	if err != nil {
		t.Fatal(err)
	}
	if server.proxy == nil || server.proxy.Tr == nil || server.proxy.Tr.Proxy == nil {
		t.Fatalf("expected configured upstream proxy function")
	}
	req, _ := http.NewRequest(http.MethodGet, "https://api.openai.com/v1/models", nil)
	proxyURL, err := server.proxy.Tr.Proxy(req)
	if err != nil {
		t.Fatal(err)
	}
	if proxyURL == nil || proxyURL.String() != "http://127.0.0.1:19001" {
		t.Fatalf("unexpected upstream proxy URL: %v", proxyURL)
	}
}

func TestShouldBypassRequestBodyInspection(t *testing.T) {
	t.Run("known-size json body", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", strings.NewReader(`{"message":"hi"}`))
		req.Header.Set("Content-Type", "application/json")
		if shouldBypassRequestBodyInspection(req) {
			t.Fatalf("expected known-size JSON request to be inspected")
		}
	})

	t.Run("streaming unknown content length", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", nil)
		req.Body = staticReadCloser{Reader: strings.NewReader("chunk")}
		req.ContentLength = -1
		req.Header.Set("Content-Type", "application/json")
		if !shouldBypassRequestBodyInspection(req) {
			t.Fatalf("expected streaming request body inspection to be bypassed")
		}
	})

	t.Run("event stream content type", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses", nil)
		req.Body = staticReadCloser{Reader: strings.NewReader("data: ping\n\n")}
		req.ContentLength = -1
		req.Header.Set("Content-Type", "text/event-stream")
		if !shouldBypassRequestBodyInspection(req) {
			t.Fatalf("expected event-stream request body inspection to be bypassed")
		}
	})

	t.Run("websocket upgrade", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "https://chatgpt.com/socket", nil)
		req.Body = staticReadCloser{Reader: strings.NewReader("")}
		req.Header.Set("Upgrade", "websocket")
		if !shouldBypassRequestBodyInspection(req) {
			t.Fatalf("expected websocket upgrade body inspection to be bypassed")
		}
	})
}

func TestHostMatchesPassthrough(t *testing.T) {
	patterns := []string{"chatgpt.com", ".chatgpt.com"}
	if !hostMatchesPassthrough("chatgpt.com", patterns) {
		t.Fatalf("expected exact match")
	}
	if !hostMatchesPassthrough("ab.chatgpt.com", patterns) {
		t.Fatalf("expected subdomain match")
	}
	if hostMatchesPassthrough("api.openai.com", patterns) {
		t.Fatalf("did not expect unrelated host match")
	}
}

func TestBudgetTrackingReadCloserSSE(t *testing.T) {
	controller := budget.New(10, "block")
	costEvents := make(chan ui.Event, 1)
	body := "data: {\"model\":\"gpt-4.1\",\"usage\":{\"prompt_tokens\":1000,\"completion_tokens\":500,\"total_tokens\":1500}}\n\n"
	rc := newBudgetTrackingReadCloser(io.NopCloser(strings.NewReader(body)), "api.openai.com", "/v1/chat/completions", controller, func(e ui.Event) {
		if e.Action == "cost" {
			costEvents <- e
		}
	})
	if _, err := io.ReadAll(rc); err != nil {
		t.Fatal(err)
	}
	_ = rc.Close()

	if controller.Spent() <= 0 {
		t.Fatalf("expected budget spend to be updated from SSE payload")
	}
	select {
	case <-costEvents:
	case <-time.After(2 * time.Second):
		t.Fatalf("expected cost event from SSE tracker")
	}
}

func TestResponseSanitizeDoesNotDoubleCountRequests(t *testing.T) {
	s := &Server{
		opts:  Options{Mode: "balanced"},
		stats: Stats{HostCounts: map[string]int{}, BlockedHosts: map[string]int{}},
	}
	s.emit(ui.Event{Action: "allow", Method: "POST", Host: "api.openai.com", Path: "/v1/chat/completions"})
	s.emit(ui.Event{Action: "r_clean", Method: "POST", Host: "api.openai.com", Path: "/v1/chat/completions", Direction: "response", Sanitizers: []string{"openai_api_key"}})

	st := s.Stats()
	if st.Requests != 1 {
		t.Fatalf("expected single request count, got %d", st.Requests)
	}
	if st.Sanitized != 1 {
		t.Fatalf("expected sanitized count 1, got %d", st.Sanitized)
	}
}

func TestBudgetExceededReturns402WithPayload(t *testing.T) {
	eng, err := rules.New("balanced", nil)
	if err != nil {
		t.Fatal(err)
	}
	san, err := sanitize.New(sanitize.Config{Enabled: true, MaxBodyBytes: 1024 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	manager := ca.New(t.TempDir())
	if err := manager.Ensure(); err != nil {
		t.Fatal(err)
	}
	cert, err := manager.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	logWriter, err := auditlog.NewWriter(t.TempDir()+"/log.jsonl", 10, false, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer logWriter.Close()

	controller := budget.New(0.00001, "block")
	usage := []byte(`{"model":"gpt-4.1","usage":{"prompt_tokens":1000000,"completion_tokens":1000000,"total_tokens":2000000}}`)
	_, _ = controller.ObserveResponse("api.openai.com", usage)

	server, err := New(Options{
		Addr:      "127.0.0.1:18726",
		Mode:      "balanced",
		CACert:    cert,
		Engine:    eng,
		Sanitizer: san,
		Guard:     response.New("detect", san),
		Budget:    controller,
		UI:        ui.NewInline(io.Discard, true, false, true),
		Log:       logWriter,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := server.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer stopCancel()
		_ = server.Stop(stopCtx)
	})

	proxyURL, _ := url.Parse("http://127.0.0.1:18726")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get("http://api.openai.com/v1/chat/completions")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPaymentRequired {
		t.Fatalf("expected 402 for budget exceeded, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("expected valid json payload: %v", err)
	}
	if payload["error"] != "budget exceeded" {
		t.Fatalf("unexpected payload: %s", string(body))
	}
	if _, ok := payload["spent_usd"]; !ok {
		t.Fatalf("expected spent_usd in payload: %s", string(body))
	}
	if _, ok := payload["budget_usd"]; !ok {
		t.Fatalf("expected budget_usd in payload: %s", string(body))
	}
}

func TestPinnedHostExtractionAndCache(t *testing.T) {
	msg := "[001] WARN: Cannot handshake client api.some-pinned-host.com:443 remote error: tls: bad certificate"
	host := extractPinnedHost(msg)
	if host != "api.some-pinned-host.com" {
		t.Fatalf("unexpected pinned host extraction: %s", host)
	}

	s := &Server{pinnedHosts: map[string]struct{}{}}
	s.markPinnedHost("api.some-pinned-host.com:443")
	if !s.isPinnedHost("api.some-pinned-host.com") {
		t.Fatalf("expected host to be marked as pinned")
	}
}

func TestRecorderCapturesSSEResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: {\"delta\":\"hello\"}\n\n")
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	eng, err := rules.New("balanced", nil)
	if err != nil {
		t.Fatal(err)
	}
	san, err := sanitize.New(sanitize.Config{Enabled: true, MaxBodyBytes: 1024 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	manager := ca.New(t.TempDir())
	if err := manager.Ensure(); err != nil {
		t.Fatal(err)
	}
	cert, err := manager.TLSCertificate()
	if err != nil {
		t.Fatal(err)
	}
	logWriter, err := auditlog.NewWriter(t.TempDir()+"/log.jsonl", 10, false, 0, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	defer logWriter.Close()

	replayPath := filepath.Join(t.TempDir(), "session.jsonl")
	recorder, err := replay.NewRecorder(replayPath)
	if err != nil {
		t.Fatal(err)
	}

	server, err := New(Options{
		Addr:      "127.0.0.1:18727",
		Mode:      "balanced",
		CACert:    cert,
		Engine:    eng,
		Sanitizer: san,
		Guard:     response.New("sanitize", san),
		UI:        ui.NewInline(io.Discard, true, false, true),
		Log:       logWriter,
		Recorder:  recorder,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := server.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer stopCancel()
		_ = server.Stop(stopCtx)
	})

	proxyURL, _ := url.Parse("http://127.0.0.1:18727")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(upstream.URL + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	player, err := replay.Load(replayPath)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, upstream.URL+"/stream", nil)
	entry, ok := player.FindResponse(req, nil)
	if !ok {
		t.Fatalf("expected SSE response to be recorded")
	}
	if entry.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status in recorded response: %d", entry.StatusCode)
	}
	if !strings.Contains(string(entry.Body), "data:") {
		t.Fatalf("expected SSE payload in recorded body")
	}
}
