package response

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/balyakin/agentwall/internal/sanitize"
)

func BenchmarkFirstTokenLatencySSE(b *testing.B) {
	s, err := sanitize.New(sanitize.Config{Enabled: true, MaxBodyBytes: 2 * 1024 * 1024})
	if err != nil {
		b.Fatal(err)
	}
	g := New("sanitize", s)

	payload := bytes.Repeat([]byte("data: hello\n\n"), 10_000)
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest(http.MethodGet, "https://api.openai.com/v1/chat/completions", nil)
		resp := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: io.NopCloser(bytes.NewReader(payload)), Request: req}
		out, _, err := g.Handle(resp)
		if err != nil {
			b.Fatal(err)
		}
		buf := make([]byte, 1)
		if _, err := out.Body.Read(buf); err != nil {
			b.Fatal(err)
		}
		_ = out.Body.Close()
	}
}
