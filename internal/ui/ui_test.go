package ui

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestInlinePrintAndSummary(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewInline(buf, true, false, false)
	w.Banner("v0.1.0", "balanced", "127.0.0.1:8723", "claude")
	w.Print(Event{TS: time.Unix(0, 0).UTC(), Action: "allow", Method: "POST", Host: "api.anthropic.com", Path: "/v1/messages"})
	w.PrintSummary(Summary{Duration: time.Second, Requests: 1, Allowed: 1}, "~/.agentwall/log.jsonl")
	text := buf.String()
	if !strings.Contains(text, "AgentWall") {
		t.Fatalf("expected banner in output")
	}
	if !strings.Contains(text, "ALLOW") {
		t.Fatalf("expected event label")
	}
	if !strings.Contains(text, "summary") {
		t.Fatalf("expected summary output")
	}
}

func TestInlineMutedEventsStillShowsSummary(t *testing.T) {
	buf := &bytes.Buffer{}
	w := NewInline(buf, true, false, false)
	w.SetEventsMuted(true)
	w.Print(Event{TS: time.Unix(0, 0).UTC(), Action: "allow", Method: "GET", Host: "api.openai.com", Path: "/v1/models"})
	w.PrintSummary(Summary{Duration: time.Second, Requests: 1, Allowed: 1}, "~/.agentwall/log.jsonl")
	text := buf.String()
	if strings.Contains(text, "ALLOW") {
		t.Fatalf("expected events to be muted")
	}
	if !strings.Contains(text, "summary") {
		t.Fatalf("expected summary output")
	}
}
