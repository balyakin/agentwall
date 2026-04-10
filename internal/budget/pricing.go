package budget

type ModelPrice struct {
	InputPerMillion      float64
	OutputPerMillion     float64
	CacheWritePerMillion float64
	CacheReadPerMillion  float64
}

var BuiltinPricing = map[string]map[string]ModelPrice{
	"anthropic": {
		"claude-3-7-sonnet": {InputPerMillion: 3.00, OutputPerMillion: 15.00, CacheWritePerMillion: 3.75, CacheReadPerMillion: 0.30},
		"claude-3-5-sonnet": {InputPerMillion: 3.00, OutputPerMillion: 15.00, CacheWritePerMillion: 3.75, CacheReadPerMillion: 0.30},
		"default":           {InputPerMillion: 3.00, OutputPerMillion: 15.00, CacheWritePerMillion: 3.75, CacheReadPerMillion: 0.30},
	},
	"openai": {
		"gpt-4.1":     {InputPerMillion: 2.00, OutputPerMillion: 8.00},
		"gpt-4o":      {InputPerMillion: 5.00, OutputPerMillion: 15.00},
		"gpt-4o-mini": {InputPerMillion: 0.15, OutputPerMillion: 0.60},
		"default":     {InputPerMillion: 2.50, OutputPerMillion: 10.00},
	},
	"google": {
		"gemini-2.5-pro":   {InputPerMillion: 3.50, OutputPerMillion: 10.50},
		"gemini-2.5-flash": {InputPerMillion: 0.35, OutputPerMillion: 1.05},
		"default":          {InputPerMillion: 1.00, OutputPerMillion: 3.00},
	},
}
