package budget

import (
	"strings"
	"testing"
)

func TestParseBudget(t *testing.T) {
	tests := []struct {
		in   string
		want float64
	}{
		{"$5", 5},
		{"5$", 5},
		{"USD:5", 5},
		{"5.00", 5},
		{"", 0},
	}
	for _, tt := range tests {
		got, err := ParseBudget(tt.in)
		if err != nil {
			t.Fatalf("ParseBudget(%q) returned error: %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("ParseBudget(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestExtractUsageOpenAI(t *testing.T) {
	body := []byte(`{"model":"gpt-4.1","usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}`)
	u, model, ok := ExtractUsage("openai", body)
	if !ok {
		t.Fatalf("expected usage extraction success")
	}
	if model != "gpt-4.1" {
		t.Fatalf("unexpected model: %s", model)
	}
	if u.TotalTokens != 1500 {
		t.Fatalf("unexpected tokens: %+v", u)
	}
}

func TestBudgetExceeded(t *testing.T) {
	c := New(0.00001, "block")
	body := []byte(`{"model":"gpt-4.1","usage":{"prompt_tokens":1000000,"completion_tokens":1000000,"total_tokens":2000000}}`)
	ev, ok := c.ObserveResponse("api.openai.com", body)
	if !ok {
		t.Fatalf("expected observe success")
	}
	if !ev.Exceeded {
		t.Fatalf("expected budget exceeded")
	}
	if !c.ShouldBlockRequest("api.openai.com") {
		t.Fatalf("expected future requests to be blocked")
	}
}

func TestExtractUsageFromSSE(t *testing.T) {
	body := []byte("data: {\"model\":\"gpt-4.1\",\"usage\":{\"prompt_tokens\":1000,\"completion_tokens\":500,\"total_tokens\":1500}}\n\n")
	u, model, ok := ExtractUsageFromSSE("openai", body)
	if !ok {
		t.Fatalf("expected usage extraction from sse")
	}
	if model != "gpt-4.1" {
		t.Fatalf("unexpected model: %s", model)
	}
	if u.TotalTokens != 1500 {
		t.Fatalf("unexpected total tokens: %v", u.TotalTokens)
	}
}

func TestExtractUsageFromSSECumulativeUsesMax(t *testing.T) {
	body := []byte(strings.Join([]string{
		"data: {\"model\":\"gpt-4.1\",\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":50,\"total_tokens\":150}}",
		"data: {\"model\":\"gpt-4.1\",\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":80,\"total_tokens\":180}}",
		"",
	}, "\n"))
	u, _, ok := ExtractUsageFromSSE("openai", body)
	if !ok {
		t.Fatalf("expected usage extraction from cumulative sse")
	}
	if u.InputTokens != 100 || u.OutputTokens != 80 || u.TotalTokens != 180 {
		t.Fatalf("expected max-based cumulative extraction, got %+v", u)
	}
}

func TestExtractUsageFromSSEDeltaSumsWhenNotMonotonic(t *testing.T) {
	body := []byte(strings.Join([]string{
		"data: {\"model\":\"gpt-4.1\",\"usage\":{\"completion_tokens\":5}}",
		"data: {\"model\":\"gpt-4.1\",\"usage\":{\"completion_tokens\":2}}",
		"data: {\"model\":\"gpt-4.1\",\"usage\":{\"completion_tokens\":7}}",
		"",
	}, "\n"))
	u, _, ok := ExtractUsageFromSSE("openai", body)
	if !ok {
		t.Fatalf("expected usage extraction from delta-like sse")
	}
	if u.OutputTokens != 14 {
		t.Fatalf("expected delta sum output=14, got %+v", u)
	}
}
