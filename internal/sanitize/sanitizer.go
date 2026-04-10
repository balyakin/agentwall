package sanitize

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/andybalholm/brotli"
)

type PatternDef struct {
	ID             string
	Pattern        string
	Replacement    string
	HighConfidence bool
}

type pattern struct {
	PatternDef
	re *regexp.Regexp
}

type Config struct {
	Enabled      bool
	MaxBodyBytes int
	Custom       []PatternDef
}

type Result struct {
	Applied       []string
	Truncated     bool
	SkippedBinary bool
}

type Sanitizer struct {
	enabled      bool
	maxBodyBytes int
	patterns     []pattern
	envSecrets   map[string]string
}

func New(cfg Config) (*Sanitizer, error) {
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 2 * 1024 * 1024
	}
	defs := append([]PatternDef{}, BuiltinPatterns...)
	defs = append(defs, cfg.Custom...)
	compiled := make([]pattern, 0, len(defs))
	for _, d := range defs {
		re, err := regexp.Compile(d.Pattern)
		if err != nil {
			return nil, fmt.Errorf("compile sanitizer %s: %w", d.ID, err)
		}
		compiled = append(compiled, pattern{PatternDef: d, re: re})
	}
	return &Sanitizer{
		enabled:      cfg.Enabled,
		maxBodyBytes: cfg.MaxBodyBytes,
		patterns:     compiled,
		envSecrets:   map[string]string{},
	}, nil
}

func (s *Sanitizer) Enabled() bool {
	return s != nil && s.enabled
}

func (s *Sanitizer) MaxBodyBytes() int {
	if s == nil || s.maxBodyBytes <= 0 {
		return 2 * 1024 * 1024
	}
	return s.maxBodyBytes
}

func (s *Sanitizer) SetEnvSecrets(secrets map[string]string) {
	if s == nil {
		return
	}
	s.envSecrets = make(map[string]string, len(secrets))
	for k, v := range secrets {
		if len(v) >= 8 {
			s.envSecrets[k] = v
		}
	}
}

func (s *Sanitizer) SanitizeRequest(req *http.Request) (Result, error) {
	if s == nil || !s.enabled || req == nil {
		return Result{}, nil
	}
	result := Result{}

	for k, values := range req.Header {
		if strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "Proxy-Authorization") {
			continue
		}
		for i := range values {
			updated, ids := s.redactString(values[i], false)
			if len(ids) > 0 {
				values[i] = updated
				result.Applied = append(result.Applied, ids...)
			}
		}
		req.Header[k] = values
	}

	if req.Body == nil {
		result.Applied = uniq(result.Applied)
		return result, nil
	}
	if isBinaryContentType(req.Header.Get("Content-Type")) {
		result.SkippedBinary = true
		result.Applied = uniq(result.Applied)
		return result, nil
	}

	raw, err := io.ReadAll(req.Body)
	if err != nil {
		return result, err
	}
	_ = req.Body.Close()

	encoding := strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Encoding")))
	decoded, err := decodeBody(raw, encoding)
	if err != nil {
		req.Body = io.NopCloser(bytes.NewReader(raw))
		req.ContentLength = int64(len(raw))
		return result, nil
	}
	updated := append([]byte(nil), decoded...)

	inspectSlice := updated
	inspectedLen := len(inspectSlice)
	if len(inspectSlice) > s.maxBodyBytes {
		inspectSlice = inspectSlice[:s.maxBodyBytes]
		result.Truncated = true
		inspectedLen = len(inspectSlice)
	}

	var sanitizedPart []byte
	host := req.URL.Hostname()
	if _, ok := TrustedLLMHosts[strings.ToLower(host)]; ok && strings.Contains(strings.ToLower(req.Header.Get("Content-Type")), "application/json") {
		part, ids := s.sanitizeTrustedJSON(inspectSlice)
		result.Applied = append(result.Applied, ids...)
		sanitizedPart = part
	} else {
		part, ids := s.RedactBytes(inspectSlice, false)
		result.Applied = append(result.Applied, ids...)
		sanitizedPart = part
	}

	if result.Truncated {
		tail := append([]byte(nil), updated[inspectedLen:]...)
		updated = append(append([]byte(nil), sanitizedPart...), tail...)
	} else {
		updated = sanitizedPart
	}

	encoded, err := encodeBody(updated, encoding)
	if err != nil {
		return result, err
	}

	req.Body = io.NopCloser(bytes.NewReader(encoded))
	req.ContentLength = int64(len(encoded))
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(encoded)))
	result.Applied = uniq(result.Applied)
	return result, nil
}

func (s *Sanitizer) RedactBytes(data []byte, highConfidenceOnly bool) ([]byte, []string) {
	return s.redactBytes(data, highConfidenceOnly, true)
}

func (s *Sanitizer) RedactBytesForce(data []byte, highConfidenceOnly bool) ([]byte, []string) {
	return s.redactBytes(data, highConfidenceOnly, false)
}

func (s *Sanitizer) redactBytes(data []byte, highConfidenceOnly bool, honorEnabled bool) ([]byte, []string) {
	if s == nil || len(data) == 0 {
		return data, nil
	}
	if honorEnabled && !s.enabled {
		return data, nil
	}
	out := append([]byte(nil), data...)
	applied := make([]string, 0)
	for _, p := range s.patterns {
		if highConfidenceOnly && !p.HighConfidence {
			continue
		}
		if p.re.Match(out) {
			out = []byte(p.re.ReplaceAllString(string(out), p.Replacement))
			applied = append(applied, p.ID)
		}
	}

	if len(s.envSecrets) > 0 {
		for name, value := range s.envSecrets {
			if value == "" {
				continue
			}
			replacement := []byte("***REDACTED:ENV:" + name + "***")
			if bytes.Contains(out, []byte(value)) {
				out = bytes.ReplaceAll(out, []byte(value), replacement)
				applied = append(applied, "env:"+name)
			}
		}
	}

	return out, uniq(applied)
}

func (s *Sanitizer) redactString(value string, highConfidenceOnly bool) (string, []string) {
	redacted, ids := s.RedactBytes([]byte(value), highConfidenceOnly)
	return string(redacted), ids
}

func (s *Sanitizer) sanitizeTrustedJSON(data []byte) ([]byte, []string) {
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return s.RedactBytes(data, false)
	}
	applied := make([]string, 0)
	walkJSON(&decoded, false, func(v string) string {
		out, ids := s.redactString(v, false)
		applied = append(applied, ids...)
		return out
	})
	marshaled, err := json.Marshal(decoded)
	if err != nil {
		return s.RedactBytes(data, false)
	}
	return marshaled, uniq(applied)
}

func walkJSON(node *any, allowArrayStringMutate bool, mutate func(string) string) {
	switch typed := (*node).(type) {
	case map[string]any:
		for k, child := range typed {
			fieldAllowsText := shouldSanitizeJSONField(k)
			switch v := child.(type) {
			case string:
				if fieldAllowsText || allowArrayStringMutate {
					typed[k] = mutate(v)
				}
			default:
				c := child
				walkJSON(&c, allowArrayStringMutate || fieldAllowsText, mutate)
				typed[k] = c
			}
		}
	case []any:
		for i, child := range typed {
			switch v := child.(type) {
			case string:
				if allowArrayStringMutate {
					typed[i] = mutate(v)
				}
			default:
				c := child
				walkJSON(&c, allowArrayStringMutate, mutate)
				typed[i] = c
			}
		}
	}
}

func shouldSanitizeJSONField(key string) bool {
	key = strings.ToLower(key)
	switch key {
	case "content", "input", "prompt", "system", "instructions", "text":
		return true
	default:
		return false
	}
}

func decodeBody(raw []byte, encoding string) ([]byte, error) {
	if len(raw) == 0 {
		return raw, nil
	}
	var reader io.Reader = bytes.NewReader(raw)
	switch encoding {
	case "", "identity":
		return raw, nil
	case "gzip":
		gz, err := gzip.NewReader(reader)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		return io.ReadAll(gz)
	case "deflate":
		fr := flate.NewReader(reader)
		defer fr.Close()
		return io.ReadAll(fr)
	case "br":
		return io.ReadAll(brotli.NewReader(reader))
	default:
		return raw, nil
	}
}

func encodeBody(raw []byte, encoding string) ([]byte, error) {
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

func isBinaryContentType(contentType string) bool {
	ct := strings.ToLower(contentType)
	return strings.Contains(ct, "application/octet-stream") ||
		strings.HasPrefix(ct, "image/") ||
		strings.HasPrefix(ct, "audio/") ||
		strings.HasPrefix(ct, "video/")
}

func uniq(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	for _, id := range in {
		if id == "" {
			continue
		}
		set[id] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
