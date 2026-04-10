package proxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/balyakin/agentwall/internal/ca"
	auditlog "github.com/balyakin/agentwall/internal/log"
	"github.com/balyakin/agentwall/internal/response"
	"github.com/balyakin/agentwall/internal/rules"
	"github.com/balyakin/agentwall/internal/sanitize"
	"github.com/balyakin/agentwall/internal/ui"
)

func BenchmarkProxyOverhead100KB(b *testing.B) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	eng, err := rules.New("balanced", nil)
	if err != nil {
		b.Fatal(err)
	}
	s, err := sanitize.New(sanitize.Config{Enabled: true, MaxBodyBytes: 2 * 1024 * 1024})
	if err != nil {
		b.Fatal(err)
	}
	m := ca.New(b.TempDir())
	if err := m.Ensure(); err != nil {
		b.Fatal(err)
	}
	cert, err := m.TLSCertificate()
	if err != nil {
		b.Fatal(err)
	}
	logWriter, err := auditlog.NewWriter(b.TempDir()+"/bench-log.jsonl", 100, false, 0, 0, false)
	if err != nil {
		b.Fatal(err)
	}
	defer logWriter.Close()

	server, err := New(Options{Addr: "127.0.0.1:18725", Mode: "balanced", CACert: cert, Engine: eng, Sanitizer: s, Guard: response.New("detect", s), UI: ui.NewInline(io.Discard, true, false, true), Log: logWriter})
	if err != nil {
		b.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := server.Start(ctx); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer stopCancel()
		_ = server.Stop(stopCtx)
	})

	proxyURL, _ := url.Parse("http://127.0.0.1:18725")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	body := bytes.Repeat([]byte("a"), 100*1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest(http.MethodPost, upstream.URL+"/v1/messages", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}
