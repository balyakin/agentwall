package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/balyakin/agentwall/internal/budget"
	auditlog "github.com/balyakin/agentwall/internal/log"
	"github.com/balyakin/agentwall/internal/replay"
	"github.com/balyakin/agentwall/internal/response"
	"github.com/balyakin/agentwall/internal/rules"
	"github.com/balyakin/agentwall/internal/sanitize"
	"github.com/balyakin/agentwall/internal/ui"
)

type Options struct {
	Addr             string
	Mode             string
	UpstreamProxy    string
	PassthroughHosts []string
	CACert           tls.Certificate
	Engine           *rules.Engine
	Sanitizer        *sanitize.Sanitizer
	Guard            *response.Guard
	Budget           *budget.Controller
	UI               *ui.Inline
	Log              *auditlog.Writer
	Recorder         *replay.Recorder
	Replayer         *replay.Player
	Explainer        *ui.Explainer
}

type Stats struct {
	Requests        int
	Allowed         int
	Blocked         int
	Sanitized       int
	Errors          int
	SecretsRedacted int
	HostCounts      map[string]int
	BlockedHosts    map[string]int
}

type Server struct {
	addr        string
	proxy       *goproxy.ProxyHttpServer
	mitmConnect *goproxy.ConnectAction
	srv         *http.Server
	opts        Options
	stats       Stats
	statsMu     sync.Mutex
	pinnedHosts map[string]struct{}
	pinnedMu    sync.RWMutex
	start       time.Time
}

func New(opts Options) (*Server, error) {
	if opts.Addr == "" {
		opts.Addr = "127.0.0.1:8723"
	}
	if opts.Engine == nil {
		eng, err := rules.New(opts.Mode, nil)
		if err != nil {
			return nil, err
		}
		opts.Engine = eng
	}

	p := goproxy.NewProxyHttpServer()
	p.Verbose = false
	mitmConnect := &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&opts.CACert)}
	p.Tr = &http.Transport{
		Proxy: nil,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	if opts.UpstreamProxy != "" {
		u, err := url.Parse(opts.UpstreamProxy)
		if err != nil {
			return nil, fmt.Errorf("invalid upstream proxy: %w", err)
		}
		p.Tr.Proxy = http.ProxyURL(u)
	}

	s := &Server{
		addr:        opts.Addr,
		proxy:       p,
		mitmConnect: mitmConnect,
		opts:        opts,
		stats:       Stats{HostCounts: map[string]int{}, BlockedHosts: map[string]int{}},
		pinnedHosts: map[string]struct{}{},
		start:       time.Now(),
	}
	p.Logger = &tlsPinningLogger{base: p.Logger, onPinned: s.markPinnedHost}
	if s.opts.Guard != nil {
		s.opts.Guard.SetStreamObserver(s.onStreamGuardResult)
	}
	s.setupHandlers()
	return s, nil
}

func (s *Server) setupHandlers() {
	s.proxy.OnRequest().HandleConnectFunc(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		req := rules.Request{Method: http.MethodConnect, Host: host, Path: ""}
		decision := s.opts.Engine.Decide(req)
		hostOnly := connectHostOnly(host)
		if decision.Action == rules.ActionBlock {
			s.emit(ui.Event{
				Action:         "block",
				Method:         "CONNECT",
				Host:           host,
				Rule:           decision.MatchedRuleID,
				DecisionSource: decision.DecisionSource,
				Mode:           s.opts.Mode,
			})
			return goproxy.RejectConnect, host
		}
		if s.opts.Budget != nil && s.opts.Budget.ShouldBlockRequest(hostOnly) {
			s.emit(ui.Event{
				Action:         "block",
				Method:         "CONNECT",
				Host:           host,
				Rule:           "budget.exceeded",
				DecisionSource: "builtin",
				Mode:           s.opts.Mode,
				Reason:         "budget exceeded",
			})
			return goproxy.RejectConnect, host
		}
		if hostMatchesPassthrough(hostOnly, s.opts.PassthroughHosts) {
			s.emit(ui.Event{
				Action:   "pass",
				Method:   "CONNECT",
				Host:     host,
				TLSMode:  "host_passthrough",
				Mode:     s.opts.Mode,
				Reason:   "configured host passthrough (no body sanitize)",
				BytesIn:  0,
				BytesOut: 0,
			})
			return goproxy.OkConnect, host
		}
		if s.isPinnedHost(hostOnly) {
			s.emit(ui.Event{
				Action:   "pass",
				Method:   "CONNECT",
				Host:     host,
				TLSMode:  "pinned_passthrough",
				Mode:     s.opts.Mode,
				Reason:   "tls-pinned passthrough (no body sanitize)",
				BytesIn:  0,
				BytesOut: 0,
			})
			return goproxy.OkConnect, host
		}
		return s.mitmConnect, host
	})

	s.proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		if req == nil || req.URL == nil {
			return req, nil
		}

		skipBodyInspection := shouldBypassRequestBodyInspection(req)
		reqBody := []byte(nil)
		if !skipBodyInspection {
			needFullBodyForKey := s.opts.Replayer != nil || s.opts.Recorder != nil
			captured, err := s.captureRequestBody(req, needFullBodyForKey)
			if err != nil {
				s.emit(ui.Event{Action: "error", Method: req.Method, Host: req.URL.Hostname(), Path: req.URL.Path, Reason: err.Error()})
				s.statsIncError()
				return req, blockedResponse(req, "request.read_error")
			}
			reqBody = captured
		}
		ctx.UserData = append([]byte(nil), reqBody...)

		if s.opts.Replayer != nil {
			if entry, ok := s.opts.Replayer.FindResponse(req, reqBody); ok {
				resp := &http.Response{
					StatusCode:    entry.StatusCode,
					Status:        fmt.Sprintf("%d %s", entry.StatusCode, http.StatusText(entry.StatusCode)),
					Proto:         "HTTP/1.1",
					ProtoMajor:    1,
					ProtoMinor:    1,
					Header:        entry.Headers,
					Body:          io.NopCloser(bytes.NewReader(entry.Body)),
					ContentLength: int64(len(entry.Body)),
					Request:       req,
				}
				s.emit(ui.Event{Action: "allow", Method: req.Method, Host: req.URL.Hostname(), Path: req.URL.Path, Reason: "replay_hit"})
				return req, resp
			}
			s.emit(ui.Event{Action: "block", Method: req.Method, Host: req.URL.Hostname(), Path: req.URL.Path, Rule: "replay.miss", DecisionSource: "builtin"})
			return req, blockedResponse(req, "replay.miss")
		}

		decision := s.opts.Engine.Decide(rules.Request{
			Method:   req.Method,
			Host:     req.URL.Hostname(),
			Path:     req.URL.Path,
			RawQuery: req.URL.RawQuery,
			Headers:  req.Header,
			Body:     reqBody,
		})

		if s.opts.Explainer != nil {
			line := fmt.Sprintf("%s %s%s", req.Method, req.URL.Host, req.URL.Path)
			decisionUI := s.opts.Explainer.Decide(req.URL.Hostname(), line)
			switch decisionUI {
			case ui.ExplainBlock:
				decision.Action = rules.ActionBlock
			case ui.ExplainSanitize:
				decision.Action = rules.ActionSanitize
			}
		}

		if decision.Action != rules.ActionBlock && s.opts.Budget != nil && s.opts.Budget.ShouldBlockRequest(req.URL.Hostname()) {
			decision.Action = rules.ActionBlock
			decision.MatchedRuleID = "budget.exceeded"
			decision.DecisionSource = "builtin"
		}

		if decision.Action == rules.ActionBlock {
			event := ui.Event{
				Action:         "block",
				Method:         req.Method,
				Host:           req.URL.Hostname(),
				Path:           req.URL.Path,
				Rule:           decision.MatchedRuleID,
				DecisionSource: decision.DecisionSource,
				MatchedRuleID:  decision.MatchedRuleID,
				MatchedFields:  decision.MatchedFields,
				Mode:           s.opts.Mode,
			}
			if decision.MatchedRuleID == "budget.exceeded" {
				event.SessionSpent = s.opts.Budget.Spent()
				event.BudgetUSD = s.opts.Budget.Budget()
				event.Reason = fmt.Sprintf("budget.exceeded ($%.2f > $%.2f)", event.SessionSpent, event.BudgetUSD)
			}
			s.emit(event)
			statusCode := http.StatusForbidden
			responseBody := []byte(`{"error":"blocked by agentwall","rule":"` + decision.MatchedRuleID + `"}`)
			if decision.MatchedRuleID == "budget.exceeded" {
				statusCode = http.StatusPaymentRequired
				responseBody = budgetExceededPayload(event.SessionSpent, event.BudgetUSD)
			}
			if s.opts.Recorder != nil {
				s.opts.Recorder.RecordRequest(req.Method, req.URL.String(), s.redactHeadersForRecording(req.Header), reqBody)
				s.opts.Recorder.RecordResponse(req.Method, req.URL.String(), reqBody, statusCode, s.redactHeadersForRecording(http.Header{"Content-Type": []string{"application/json"}}), s.redactBodyForRecording(responseBody), nil)
			}
			if decision.MatchedRuleID == "budget.exceeded" {
				return req, budgetExceededResponse(req, event.SessionSpent, event.BudgetUSD)
			}
			return req, blockedResponse(req, decision.MatchedRuleID)
		}

		sanitizeRes := sanitize.Result{}
		if s.opts.Sanitizer != nil && s.opts.Sanitizer.Enabled() && !skipBodyInspection {
			res, err := s.opts.Sanitizer.SanitizeRequest(req)
			if err != nil {
				s.emit(ui.Event{Action: "error", Method: req.Method, Host: req.URL.Hostname(), Path: req.URL.Path, Reason: err.Error()})
				s.statsIncError()
			} else {
				sanitizeRes = res
			}
		}

		if s.opts.Recorder != nil {
			s.opts.Recorder.RecordRequest(req.Method, req.URL.String(), s.redactHeadersForRecording(req.Header), reqBody)
		}

		bytesOut := req.ContentLength
		if bytesOut < 0 {
			bytesOut = 0
		}

		e := ui.Event{
			Action:         "allow",
			Method:         req.Method,
			Host:           req.URL.Hostname(),
			Path:           req.URL.Path,
			DecisionSource: decision.DecisionSource,
			MatchedRuleID:  decision.MatchedRuleID,
			MatchedFields:  decision.MatchedFields,
			Mode:           s.opts.Mode,
			BytesOut:       bytesOut,
		}
		if len(sanitizeRes.Applied) > 0 {
			e.Action = "clean"
			e.Sanitizers = sanitizeRes.Applied
		}
		if sanitizeRes.Truncated {
			e.Reason = "truncated=true"
		}
		if sanitizeRes.SkippedBinary {
			e.Reason = "sanitize_skipped_binary"
		}
		if skipBodyInspection {
			e.Reason = "body_inspection_skipped_streaming"
		}
		s.emit(e)
		return req, nil
	})

	s.proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp == nil || resp.Request == nil || resp.Request.URL == nil {
			return resp
		}
		reqBodyForKey := requestBodyFromCtx(ctx)
		host := resp.Request.URL.Hostname()
		path := resp.Request.URL.Path
		contentType := strings.ToLower(resp.Header.Get("Content-Type"))
		isSSE := strings.Contains(contentType, "text/event-stream")

		if s.opts.Budget != nil {
			if isSSE {
				resp.Body = newBudgetTrackingReadCloser(resp.Body, host, path, s.opts.Budget, s.emit)
			} else {
				body, err := io.ReadAll(resp.Body)
				if err == nil {
					_ = resp.Body.Close()
					resp.Body = io.NopCloser(bytes.NewReader(body))
					resp.ContentLength = int64(len(body))
					if ev, ok := s.opts.Budget.ObserveResponse(host, body); ok {
						s.emit(ui.Event{Action: "cost", Provider: ev.Provider, Model: ev.Model, SessionSpent: ev.SpentUSD, BudgetUSD: ev.Budget, Host: host, Path: path})
					}
				}
			}
		}

		if s.opts.Guard != nil {
			updated, result, err := s.opts.Guard.Handle(resp)
			if err != nil {
				s.emit(ui.Event{Action: "error", Method: resp.Request.Method, Host: host, Path: path, Reason: err.Error()})
				s.statsIncError()
				return resp
			}
			resp = updated
			if result.Blocked {
				s.emit(ui.Event{Action: "block", Method: resp.Request.Method, Host: host, Path: path, Rule: "response.guard", Direction: "response", DecisionSource: "builtin"})
			} else if len(result.Applied) > 0 {
				s.emit(ui.Event{Action: "r_clean", Method: resp.Request.Method, Host: host, Path: path, Sanitizers: result.Applied, Direction: "response"})
			}
		}

		if s.opts.Recorder != nil {
			if isSSE {
				method := resp.Request.Method
				rawURL := resp.Request.URL.String()
				statusCode := resp.StatusCode
				headers := s.redactHeadersForRecording(resp.Header)
				resp.Body = newReplayRecordingReadCloser(resp.Body, 4*1024*1024, func(body []byte) {
					s.opts.Recorder.RecordResponse(method, rawURL, reqBodyForKey, statusCode, headers, s.redactBodyForRecording(body), nil)
				})
				return resp
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
			s.opts.Recorder.RecordResponse(resp.Request.Method, resp.Request.URL.String(), reqBodyForKey, resp.StatusCode, s.redactHeadersForRecording(resp.Header), s.redactBodyForRecording(body), nil)
		}
		return resp
	})
}

func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.srv = &http.Server{Handler: s.proxy}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutdownCtx)
	}()
	go func() {
		_ = s.srv.Serve(ln)
	}()
	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	if s == nil || s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}

func (s *Server) Stats() Stats {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	copyStats := s.stats
	copyStats.HostCounts = copyMap(s.stats.HostCounts)
	copyStats.BlockedHosts = copyMap(s.stats.BlockedHosts)
	return copyStats
}

func (s *Server) Duration() time.Duration {
	return time.Since(s.start)
}

func (s *Server) emit(event ui.Event) {
	if event.TS.IsZero() {
		event.TS = time.Now().UTC()
	}
	if event.Mode == "" {
		event.Mode = s.opts.Mode
	}
	if s.opts.UI != nil {
		s.opts.UI.Print(event)
	}
	if s.opts.Log != nil {
		_ = s.opts.Log.Write(event)
	}
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	isResponse := strings.EqualFold(event.Direction, "response")
	if event.Host != "" {
		s.stats.HostCounts[event.Host]++
	}
	switch event.Action {
	case "allow", "pass":
		if !isResponse {
			s.stats.Requests++
		}
		s.stats.Allowed++
	case "clean":
		if !isResponse {
			s.stats.Requests++
		}
		s.stats.Sanitized++
		s.stats.SecretsRedacted += len(event.Sanitizers)
	case "r_clean":
		s.stats.Sanitized++
		s.stats.SecretsRedacted += len(event.Sanitizers)
	case "block":
		if !isResponse {
			s.stats.Requests++
		}
		s.stats.Blocked++
		if event.Host != "" {
			s.stats.BlockedHosts[event.Host]++
		}
	case "error":
		s.stats.Errors++
	}
}

func (s *Server) statsIncError() {
	s.statsMu.Lock()
	defer s.statsMu.Unlock()
	s.stats.Errors++
}

func (s *Server) onStreamGuardResult(req *http.Request, result response.Result) {
	if req == nil || req.URL == nil {
		return
	}
	host := req.URL.Hostname()
	path := req.URL.Path
	if result.Blocked {
		s.emit(ui.Event{
			Action:         "block",
			Method:         req.Method,
			Host:           host,
			Path:           path,
			Rule:           "response.guard",
			Direction:      "response",
			DecisionSource: "builtin",
			Sanitizers:     result.Applied,
		})
		return
	}
	if len(result.Applied) > 0 {
		s.emit(ui.Event{
			Action:     "r_clean",
			Method:     req.Method,
			Host:       host,
			Path:       path,
			Direction:  "response",
			Sanitizers: result.Applied,
		})
	}
}

type budgetTrackingReadCloser struct {
	src        io.ReadCloser
	host       string
	path       string
	controller *budget.Controller
	emit       func(ui.Event)
	buf        bytes.Buffer
	maxCapture int
	once       sync.Once
}

func newBudgetTrackingReadCloser(src io.ReadCloser, host, path string, controller *budget.Controller, emit func(ui.Event)) io.ReadCloser {
	return &budgetTrackingReadCloser{
		src:        src,
		host:       host,
		path:       path,
		controller: controller,
		emit:       emit,
		maxCapture: 4 * 1024 * 1024,
	}
}

func (b *budgetTrackingReadCloser) Read(p []byte) (int, error) {
	n, err := b.src.Read(p)
	if n > 0 {
		remaining := b.maxCapture - b.buf.Len()
		if remaining > 0 {
			if n < remaining {
				_, _ = b.buf.Write(p[:n])
			} else {
				_, _ = b.buf.Write(p[:remaining])
			}
		}
	}
	if err == io.EOF {
		b.finalize()
	}
	return n, err
}

func (b *budgetTrackingReadCloser) Close() error {
	b.finalize()
	return b.src.Close()
}

func (b *budgetTrackingReadCloser) finalize() {
	b.once.Do(func() {
		if b.controller == nil {
			return
		}
		if ev, ok := b.controller.ObserveResponse(b.host, b.buf.Bytes()); ok && b.emit != nil {
			b.emit(ui.Event{Action: "cost", Provider: ev.Provider, Model: ev.Model, SessionSpent: ev.SpentUSD, BudgetUSD: ev.Budget, Host: b.host, Path: b.path})
		}
	})
}

type replayRecordingReadCloser struct {
	src        io.ReadCloser
	buf        bytes.Buffer
	maxCapture int
	finalizeFn func([]byte)
	once       sync.Once
}

type multiReadCloser struct {
	io.Reader
	closer io.Closer
}

func (m *multiReadCloser) Close() error {
	if m == nil || m.closer == nil {
		return nil
	}
	return m.closer.Close()
}

func newReplayRecordingReadCloser(src io.ReadCloser, maxCapture int, finalizeFn func([]byte)) io.ReadCloser {
	if maxCapture <= 0 {
		maxCapture = 4 * 1024 * 1024
	}
	return &replayRecordingReadCloser{src: src, maxCapture: maxCapture, finalizeFn: finalizeFn}
}

func (r *replayRecordingReadCloser) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	if n > 0 {
		remaining := r.maxCapture - r.buf.Len()
		if remaining > 0 {
			if n <= remaining {
				_, _ = r.buf.Write(p[:n])
			} else {
				_, _ = r.buf.Write(p[:remaining])
			}
		}
	}
	if err == io.EOF {
		r.finalize()
	}
	return n, err
}

func (r *replayRecordingReadCloser) Close() error {
	r.finalize()
	return r.src.Close()
}

func (r *replayRecordingReadCloser) finalize() {
	r.once.Do(func() {
		if r.finalizeFn != nil {
			r.finalizeFn(r.buf.Bytes())
		}
	})
}

func requestBodyFromCtx(ctx *goproxy.ProxyCtx) []byte {
	if ctx == nil || ctx.UserData == nil {
		return nil
	}
	body, ok := ctx.UserData.([]byte)
	if !ok || len(body) == 0 {
		return nil
	}
	return append([]byte(nil), body...)
}

func shouldBypassRequestBodyInspection(req *http.Request) bool {
	if req == nil || req.Body == nil {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(req.Header.Get("Upgrade")), "websocket") {
		return true
	}
	contentType := strings.ToLower(strings.TrimSpace(req.Header.Get("Content-Type")))
	if strings.Contains(contentType, "text/event-stream") {
		return true
	}
	if req.ContentLength < 0 {
		return true
	}
	return false
}

func (s *Server) requestBodyPreviewLimit() int {
	if s.opts.Sanitizer != nil {
		return s.opts.Sanitizer.MaxBodyBytes()
	}
	return 2 * 1024 * 1024
}

func (s *Server) captureRequestBody(req *http.Request, full bool) ([]byte, error) {
	if req == nil || req.Body == nil {
		return nil, nil
	}
	if full {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
		return body, nil
	}
	limit := s.requestBodyPreviewLimit()
	if limit <= 0 {
		limit = 2 * 1024 * 1024
	}
	peek, err := io.ReadAll(io.LimitReader(req.Body, int64(limit+1)))
	if err != nil {
		return nil, err
	}
	body := append([]byte(nil), peek...)
	if len(body) > limit {
		body = body[:limit]
	}
	original := req.Body
	req.Body = &multiReadCloser{Reader: io.MultiReader(bytes.NewReader(peek), original), closer: original}
	return body, nil
}

func (s *Server) redactBodyForRecording(body []byte) []byte {
	if len(body) == 0 {
		return nil
	}
	if s.opts.Sanitizer == nil {
		return append([]byte(nil), body...)
	}
	redacted, _ := s.opts.Sanitizer.RedactBytesForce(body, false)
	return redacted
}

func (s *Server) redactHeadersForRecording(in http.Header) http.Header {
	out := http.Header{}
	for key, values := range in {
		copied := append([]string(nil), values...)
		for i := range copied {
			if strings.EqualFold(key, "Authorization") || strings.EqualFold(key, "Proxy-Authorization") {
				copied[i] = "***REDACTED:AUTH_HEADER***"
				continue
			}
			copied[i] = string(s.redactBodyForRecording([]byte(copied[i])))
		}
		out[key] = copied
	}
	return out
}

func (s *Server) markPinnedHost(host string) {
	host = connectHostOnly(host)
	if host == "" {
		return
	}
	s.pinnedMu.Lock()
	defer s.pinnedMu.Unlock()
	s.pinnedHosts[host] = struct{}{}
}

func (s *Server) isPinnedHost(host string) bool {
	host = connectHostOnly(host)
	if host == "" {
		return false
	}
	s.pinnedMu.RLock()
	defer s.pinnedMu.RUnlock()
	_, ok := s.pinnedHosts[host]
	return ok
}

func connectHostOnly(host string) string {
	host = strings.TrimSpace(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	return strings.ToLower(host)
}

func hostMatchesPassthrough(host string, patterns []string) bool {
	host = connectHostOnly(host)
	if host == "" {
		return false
	}
	for _, raw := range patterns {
		pattern := connectHostOnly(raw)
		if pattern == "" {
			continue
		}
		if host == pattern {
			return true
		}
		if strings.HasPrefix(pattern, ".") {
			if strings.HasSuffix(host, pattern) {
				return true
			}
			continue
		}
		if strings.HasSuffix(host, "."+pattern) {
			return true
		}
	}
	return false
}

type tlsPinningLogger struct {
	base     goproxy.Logger
	onPinned func(host string)
}

func (l *tlsPinningLogger) Printf(format string, argv ...any) {
	msg := fmt.Sprintf(format, argv...)
	if host := extractPinnedHost(msg); host != "" && l.onPinned != nil {
		l.onPinned(host)
	}
	if l.base != nil {
		l.base.Printf(format, argv...)
	}
}

func extractPinnedHost(msg string) string {
	const marker = "Cannot handshake client "
	idx := strings.Index(msg, marker)
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(msg[idx+len(marker):])
	if rest == "" {
		return ""
	}
	parts := strings.Fields(rest)
	if len(parts) == 0 {
		return ""
	}
	return connectHostOnly(parts[0])
}

func budgetExceededPayload(spent, budget float64) []byte {
	payload, _ := json.Marshal(map[string]any{
		"error":      "budget exceeded",
		"spent_usd":  spent,
		"budget_usd": budget,
	})
	return payload
}

func budgetExceededResponse(req *http.Request, spent, budget float64) *http.Response {
	payload := budgetExceededPayload(spent, budget)
	return &http.Response{
		StatusCode:    http.StatusPaymentRequired,
		Status:        "402 Payment Required",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"application/json"}, "Content-Length": []string{fmt.Sprintf("%d", len(payload))}},
		Body:          io.NopCloser(bytes.NewReader(payload)),
		ContentLength: int64(len(payload)),
		Request:       req,
	}
}

func blockedResponse(req *http.Request, rule string) *http.Response {
	payload, _ := json.Marshal(map[string]string{
		"error": "blocked by agentwall",
		"rule":  rule,
	})
	return &http.Response{
		StatusCode:    http.StatusForbidden,
		Status:        "403 Forbidden",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"application/json"}, "Content-Length": []string{fmt.Sprintf("%d", len(payload))}},
		Body:          io.NopCloser(bytes.NewReader(payload)),
		ContentLength: int64(len(payload)),
		Request:       req,
	}
}

func copyMap(in map[string]int) map[string]int {
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
