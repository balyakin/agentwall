package response

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"

	"github.com/balyakin/agentwall/internal/sanitize"
)

type Mode string

const (
	ModeOff      Mode = "off"
	ModeDetect   Mode = "detect"
	ModeSanitize Mode = "sanitize"
	ModeBlock    Mode = "block"
)

type Result struct {
	Applied []string
	Blocked bool
}

type StreamObserver func(req *http.Request, result Result)

type Guard struct {
	mode           Mode
	sanitizer      *sanitize.Sanitizer
	streamObserver StreamObserver
}

func New(mode string, sanitizer *sanitize.Sanitizer) *Guard {
	m := Mode(strings.ToLower(mode))
	switch m {
	case ModeOff, ModeDetect, ModeSanitize, ModeBlock:
		// valid mode
	default:
		m = ModeSanitize
	}
	return &Guard{mode: m, sanitizer: sanitizer}
}

func (g *Guard) Mode() Mode {
	if g == nil {
		return ModeOff
	}
	return g.mode
}

func (g *Guard) SetStreamObserver(observer StreamObserver) {
	if g == nil {
		return
	}
	g.streamObserver = observer
}

func (g *Guard) notifyStream(req *http.Request, result Result) {
	if g == nil || g.streamObserver == nil {
		return
	}
	g.streamObserver(req, result)
}

func (g *Guard) Handle(resp *http.Response) (*http.Response, Result, error) {
	if g == nil || g.mode == ModeOff || resp == nil || resp.Body == nil || g.sanitizer == nil || !g.sanitizer.Enabled() {
		return resp, Result{}, nil
	}
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, "text/event-stream") {
		wrapped, result := g.wrapStreaming(resp)
		return wrapped, result, nil
	}

	rawBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, Result{}, err
	}
	_ = resp.Body.Close()

	encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	decodedBody, decodeErr := decodeResponseBody(rawBody, encoding)
	if decodeErr != nil {
		decodedBody = rawBody
	}

	_, highIDs := g.sanitizer.RedactBytes(decodedBody, true)
	if g.mode == ModeBlock && len(highIDs) > 0 {
		return blockResponse(resp.Request, "response guard blocked potential secret leak"), Result{Applied: highIDs, Blocked: true}, nil
	}

	redacted, ids := g.sanitizer.RedactBytes(decodedBody, false)
	result := Result{Applied: ids}
	if len(ids) == 0 {
		resp.Body = io.NopCloser(bytes.NewReader(rawBody))
		resp.ContentLength = int64(len(rawBody))
		resp.Header.Set("Content-Length", strconv.Itoa(len(rawBody)))
		return resp, result, nil
	}

	switch g.mode {
	case ModeDetect:
		resp.Body = io.NopCloser(bytes.NewReader(rawBody))
		resp.ContentLength = int64(len(rawBody))
		resp.Header.Set("Content-Length", strconv.Itoa(len(rawBody)))
		return resp, result, nil
	case ModeSanitize:
		return applySanitizedResponseBody(resp, redacted, encoding, decodeErr, result)
	case ModeBlock:
		return applySanitizedResponseBody(resp, redacted, encoding, decodeErr, result)
	default:
		resp.Body = io.NopCloser(bytes.NewReader(rawBody))
		return resp, result, nil
	}
}

func applySanitizedResponseBody(resp *http.Response, decodedRedacted []byte, encoding string, decodeErr error, result Result) (*http.Response, Result, error) {
	out := decodedRedacted
	if decodeErr == nil {
		encoded, err := encodeResponseBody(decodedRedacted, encoding)
		if err != nil {
			return resp, result, err
		}
		out = encoded
		if encoding == "" || encoding == "identity" {
			resp.Header.Del("Content-Encoding")
		}
	} else {
		// Could not decode original compressed payload safely; return sanitized plaintext.
		resp.Header.Del("Content-Encoding")
	}

	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	return resp, result, nil
}

func decodeResponseBody(raw []byte, encoding string) ([]byte, error) {
	if len(raw) == 0 {
		return raw, nil
	}
	switch encoding {
	case "", "identity":
		return raw, nil
	case "gzip":
		gr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return nil, err
		}
		defer gr.Close()
		return io.ReadAll(gr)
	case "deflate":
		fr := flate.NewReader(bytes.NewReader(raw))
		defer fr.Close()
		return io.ReadAll(fr)
	case "br":
		return io.ReadAll(brotli.NewReader(bytes.NewReader(raw)))
	default:
		return nil, fmt.Errorf("unsupported response encoding: %s", encoding)
	}
}

func encodeResponseBody(raw []byte, encoding string) ([]byte, error) {
	if len(raw) == 0 {
		return raw, nil
	}
	buf := bytes.NewBuffer(nil)
	switch encoding {
	case "", "identity":
		return raw, nil
	case "gzip":
		gw := gzip.NewWriter(buf)
		if _, err := gw.Write(raw); err != nil {
			_ = gw.Close()
			return nil, err
		}
		if err := gw.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case "deflate":
		fw, err := flate.NewWriter(buf, flate.DefaultCompression)
		if err != nil {
			return nil, err
		}
		if _, err := fw.Write(raw); err != nil {
			_ = fw.Close()
			return nil, err
		}
		if err := fw.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	case "br":
		bw := brotli.NewWriter(buf)
		if _, err := bw.Write(raw); err != nil {
			_ = bw.Close()
			return nil, err
		}
		if err := bw.Close(); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	default:
		return raw, nil
	}
}

func blockResponse(req *http.Request, reason string) *http.Response {
	payload, _ := json.Marshal(map[string]string{
		"error":  "blocked by agentwall",
		"reason": reason,
	})
	if req == nil {
		req = &http.Request{}
	}
	return &http.Response{
		StatusCode:    http.StatusForbidden,
		Status:        "403 Forbidden",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       req,
		Header:        http.Header{"Content-Type": []string{"application/json"}, "Content-Length": []string{strconv.Itoa(len(payload))}},
		Body:          io.NopCloser(bytes.NewReader(payload)),
		ContentLength: int64(len(payload)),
	}
}
