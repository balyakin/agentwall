package budget

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

type Usage struct {
	InputTokens      float64
	OutputTokens     float64
	CacheWriteTokens float64
	CacheReadTokens  float64
	TotalTokens      float64
}

type Event struct {
	Provider string
	Model    string
	AddedUSD float64
	SpentUSD float64
	Budget   float64
	Exceeded bool
}

type Controller struct {
	budgetUSD float64
	onExceed  string
	mu        sync.Mutex
	spentUSD  float64
}

func New(budgetUSD float64, onExceed string) *Controller {
	if onExceed == "" {
		onExceed = "block"
	}
	return &Controller{budgetUSD: budgetUSD, onExceed: onExceed}
}

func ParseBudget(input string) (float64, error) {
	trimmed := strings.TrimSpace(strings.ToUpper(input))
	trimmed = strings.TrimPrefix(trimmed, "USD:")
	trimmed = strings.TrimPrefix(trimmed, "$")
	trimmed = strings.TrimSuffix(trimmed, "$")
	if trimmed == "" {
		return 0, nil
	}
	v, err := strconvParseFloat(trimmed)
	if err != nil {
		return 0, fmt.Errorf("invalid budget %q", input)
	}
	if v < 0 {
		return 0, fmt.Errorf("budget must be non-negative")
	}
	return v, nil
}

func (c *Controller) Enabled() bool {
	return c != nil && c.budgetUSD > 0
}

func (c *Controller) Spent() float64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.spentUSD
}

func (c *Controller) Budget() float64 {
	if c == nil {
		return 0
	}
	return c.budgetUSD
}

func (c *Controller) Exceeded() bool {
	if c == nil || c.budgetUSD <= 0 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.spentUSD > c.budgetUSD
}

func (c *Controller) ShouldBlockRequest(host string) bool {
	if !c.Enabled() || !IsLLMHost(host) {
		return false
	}
	if strings.EqualFold(c.onExceed, "warn") {
		return false
	}
	return c.Exceeded()
}

func (c *Controller) ObserveResponse(host string, body []byte) (Event, bool) {
	if !c.Enabled() || len(body) == 0 || !IsLLMHost(host) {
		return Event{}, false
	}
	provider := DetectProvider(host, body)
	if provider == "" {
		return Event{}, false
	}
	usage, model, ok := ExtractUsage(provider, body)
	if !ok {
		usage, model, ok = ExtractUsageFromSSE(provider, body)
	}
	if !ok {
		return Event{}, false
	}
	added := CalculateCost(provider, model, usage)
	c.mu.Lock()
	c.spentUSD += added
	e := Event{
		Provider: provider,
		Model:    model,
		AddedUSD: added,
		SpentUSD: c.spentUSD,
		Budget:   c.budgetUSD,
		Exceeded: c.spentUSD > c.budgetUSD,
	}
	c.mu.Unlock()
	return e, true
}

func IsLLMHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	switch host {
	case "api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com", "api.x.ai", "api.deepseek.com", "api.groq.com", "api.mistral.ai", "openrouter.ai":
		return true
	default:
		return false
	}
}

func DetectProvider(host string, body []byte) string {
	host = strings.ToLower(strings.TrimSpace(host))
	switch host {
	case "api.anthropic.com":
		return "anthropic"
	case "api.openai.com", "openrouter.ai", "api.x.ai", "api.deepseek.com", "api.groq.com", "api.mistral.ai":
		return "openai"
	case "generativelanguage.googleapis.com":
		return "google"
	}

	text := strings.ToLower(string(body))
	switch {
	case strings.Contains(text, "usage_metadata") || strings.Contains(text, "usagemetadata"):
		return "google"
	case strings.Contains(text, "cache_creation_input_tokens"):
		return "anthropic"
	case strings.Contains(text, "prompt_tokens"):
		return "openai"
	default:
		return ""
	}
}

func ExtractUsage(provider string, body []byte) (Usage, string, bool) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return Usage{}, "", false
	}
	model := stringField(payload, "model")
	switch provider {
	case "anthropic":
		u := nestedMap(payload, "usage")
		usage := Usage{
			InputTokens:      numberField(u, "input_tokens"),
			OutputTokens:     numberField(u, "output_tokens"),
			CacheWriteTokens: numberField(u, "cache_creation_input_tokens"),
			CacheReadTokens:  numberField(u, "cache_read_input_tokens"),
		}
		usage.TotalTokens = usage.InputTokens + usage.OutputTokens + usage.CacheWriteTokens + usage.CacheReadTokens
		return usage, model, usage.TotalTokens > 0
	case "openai":
		u := nestedMap(payload, "usage")
		usage := Usage{
			InputTokens:  numberField(u, "prompt_tokens"),
			OutputTokens: numberField(u, "completion_tokens"),
			TotalTokens:  numberField(u, "total_tokens"),
		}
		if usage.TotalTokens == 0 {
			usage.TotalTokens = usage.InputTokens + usage.OutputTokens
		}
		return usage, model, usage.TotalTokens > 0
	case "google":
		u := nestedMap(payload, "usageMetadata")
		if len(u) == 0 {
			u = nestedMap(payload, "usagemetadata")
		}
		usage := Usage{
			InputTokens:  numberField(u, "promptTokenCount"),
			OutputTokens: numberField(u, "candidatesTokenCount"),
			TotalTokens:  numberField(u, "totalTokenCount"),
		}
		if usage.TotalTokens == 0 {
			usage.TotalTokens = usage.InputTokens + usage.OutputTokens
		}
		return usage, model, usage.TotalTokens > 0
	default:
		return Usage{}, model, false
	}
}

func ExtractUsageFromSSE(provider string, body []byte) (Usage, string, bool) {
	lines := strings.Split(string(body), "\n")
	inSeries := usageSeries{}
	outSeries := usageSeries{}
	cacheWriteSeries := usageSeries{}
	cacheReadSeries := usageSeries{}
	totalSeries := usageSeries{}
	model := ""
	found := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "data:") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		}
		if line == "" || line == "[DONE]" {
			continue
		}
		var payload map[string]any
		if err := json.Unmarshal([]byte(line), &payload); err != nil {
			continue
		}
		if model == "" {
			model = stringField(payload, "model")
		}

		switch provider {
		case "anthropic":
			u := nestedMap(payload, "usage")
			if u == nil {
				continue
			}
			in := numberField(u, "input_tokens")
			out := numberField(u, "output_tokens")
			cacheW := numberField(u, "cache_creation_input_tokens")
			cacheR := numberField(u, "cache_read_input_tokens")
			if in+out+cacheW+cacheR == 0 {
				continue
			}
			inSeries.add(in)
			outSeries.add(out)
			cacheWriteSeries.add(cacheW)
			cacheReadSeries.add(cacheR)
			found = true
		case "openai":
			u := nestedMap(payload, "usage")
			if u == nil {
				continue
			}
			in := numberField(u, "prompt_tokens")
			out := numberField(u, "completion_tokens")
			totalTokens := numberField(u, "total_tokens")
			if in+out+totalTokens == 0 {
				continue
			}
			inSeries.add(in)
			outSeries.add(out)
			totalSeries.add(totalTokens)
			found = true
		case "google":
			u := nestedMap(payload, "usageMetadata")
			if len(u) == 0 {
				u = nestedMap(payload, "usagemetadata")
			}
			if u == nil {
				continue
			}
			in := numberField(u, "promptTokenCount")
			out := numberField(u, "candidatesTokenCount")
			totalTokens := numberField(u, "totalTokenCount")
			if in+out+totalTokens == 0 {
				continue
			}
			inSeries.add(in)
			outSeries.add(out)
			totalSeries.add(totalTokens)
			found = true
		}
	}

	if !found {
		return Usage{}, model, false
	}
	total := Usage{
		InputTokens:      inSeries.value(),
		OutputTokens:     outSeries.value(),
		CacheWriteTokens: cacheWriteSeries.value(),
		CacheReadTokens:  cacheReadSeries.value(),
		TotalTokens:      totalSeries.value(),
	}
	if total.TotalTokens == 0 {
		total.TotalTokens = total.InputTokens + total.OutputTokens + total.CacheWriteTokens + total.CacheReadTokens
	}
	return total, model, total.TotalTokens > 0
}

type usageSeries struct {
	count     int
	sum       float64
	max       float64
	last      float64
	monotonic bool
}

func (u *usageSeries) add(v float64) {
	if v <= 0 {
		return
	}
	if u.count == 0 {
		u.monotonic = true
	} else if v < u.last {
		u.monotonic = false
	}
	u.count++
	u.sum += v
	if v > u.max {
		u.max = v
	}
	u.last = v
}

func (u usageSeries) value() float64 {
	if u.count == 0 {
		return 0
	}
	if u.count == 1 {
		return u.last
	}
	if u.monotonic {
		return u.max
	}
	return u.sum
}

func CalculateCost(provider, model string, usage Usage) float64 {
	provider = strings.ToLower(provider)
	model = strings.ToLower(model)
	pricing := BuiltinPricing[provider]
	if len(pricing) == 0 {
		return 0
	}
	selected := pricing["default"]
	for k, p := range pricing {
		if k != "default" && strings.Contains(model, strings.ToLower(k)) {
			selected = p
			break
		}
	}
	input := usage.InputTokens / 1_000_000 * selected.InputPerMillion
	output := usage.OutputTokens / 1_000_000 * selected.OutputPerMillion
	cacheWrite := usage.CacheWriteTokens / 1_000_000 * selected.CacheWritePerMillion
	cacheRead := usage.CacheReadTokens / 1_000_000 * selected.CacheReadPerMillion
	return input + output + cacheWrite + cacheRead
}

func nestedMap(input map[string]any, key string) map[string]any {
	v, ok := input[key]
	if !ok {
		return nil
	}
	m, _ := v.(map[string]any)
	return m
}

func stringField(input map[string]any, key string) string {
	v, ok := input[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func numberField(input map[string]any, key string) float64 {
	if input == nil {
		return 0
	}
	v, ok := input[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	default:
		return 0
	}
}

func strconvParseFloat(v string) (float64, error) {
	return strconv.ParseFloat(strings.TrimSpace(v), 64)
}
