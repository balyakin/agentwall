package replay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Entry struct {
	Kind       string      `json:"kind"`
	Key        string      `json:"key"`
	Method     string      `json:"method,omitempty"`
	URL        string      `json:"url,omitempty"`
	StatusCode int         `json:"status_code,omitempty"`
	Headers    http.Header `json:"headers,omitempty"`
	Body       []byte      `json:"body,omitempty"`
	Error      string      `json:"error,omitempty"`
}

type Recorder struct {
	mu  sync.Mutex
	f   *os.File
	enc *json.Encoder
}

func NewRecorder(path string) (*Recorder, error) {
	if path == "" {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	return &Recorder{f: f, enc: json.NewEncoder(f)}, nil
}

func (r *Recorder) Close() error {
	if r == nil || r.f == nil {
		return nil
	}
	return r.f.Close()
}

func RequestKey(method, rawURL string, body []byte) string {
	sum := sha256.Sum256(body)
	return method + "|" + rawURL + "|" + hex.EncodeToString(sum[:])
}

func (r *Recorder) RecordRequest(method, rawURL string, headers http.Header, body []byte) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_ = r.enc.Encode(Entry{
		Kind:    "request",
		Key:     RequestKey(method, rawURL, body),
		Method:  method,
		URL:     scrubURL(rawURL),
		Headers: scrubHeaders(headers),
	})
}

func (r *Recorder) RecordResponse(method, rawURL string, reqBody []byte, statusCode int, headers http.Header, body []byte, err error) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	entry := Entry{
		Kind:       "response",
		Key:        RequestKey(method, rawURL, reqBody),
		Method:     method,
		URL:        scrubURL(rawURL),
		StatusCode: statusCode,
		Headers:    scrubHeaders(headers),
		Body:       body,
	}
	if err != nil {
		entry.Error = err.Error()
	}
	_ = r.enc.Encode(entry)
}

func scrubURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func scrubHeaders(h http.Header) http.Header {
	cloned := cloneHeader(h)
	for key, values := range cloned {
		if strings.EqualFold(key, "Authorization") || strings.EqualFold(key, "Proxy-Authorization") {
			for i := range values {
				values[i] = "***REDACTED:AUTH_HEADER***"
			}
			cloned[key] = values
		}
	}
	return cloned
}

func cloneHeader(h http.Header) http.Header {
	out := http.Header{}
	for k, values := range h {
		copied := append([]string(nil), values...)
		out[k] = copied
	}
	return out
}
