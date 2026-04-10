package sanitize

var BuiltinPatterns = []PatternDef{
	{ID: "anthropic_api_key", Pattern: `sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}`, Replacement: "***REDACTED:ANTHROPIC_KEY***", HighConfidence: true},
	{ID: "openai_api_key", Pattern: `\b(?:sk-proj-[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9]{48})\b`, Replacement: "***REDACTED:OPENAI_KEY***", HighConfidence: true},
	{ID: "aws_access_key", Pattern: `\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`, Replacement: "***REDACTED:AWS_ACCESS_KEY***", HighConfidence: true},
	{ID: "aws_secret_key", Pattern: `(?i)(aws.{0,20}?(?:secret|key)["'\s:=]+)([A-Za-z0-9/+=]{40})`, Replacement: `${1}***REDACTED:AWS_SECRET***`},
	{ID: "github_token", Pattern: `\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b`, Replacement: "***REDACTED:GITHUB_TOKEN***", HighConfidence: true},
	{ID: "github_fine_grained", Pattern: `\bgithub_pat_[A-Za-z0-9_]{82}\b`, Replacement: "***REDACTED:GITHUB_PAT***", HighConfidence: true},
	{ID: "gcp_service_account", Pattern: `"private_key":\s*"-----BEGIN PRIVATE KEY-----[^"]+-----END PRIVATE KEY-----\\n"`, Replacement: `"private_key":"***REDACTED:GCP_KEY***"`, HighConfidence: true},
	{ID: "slack_token", Pattern: `\bxox[baprs]-[A-Za-z0-9\-]{10,}\b`, Replacement: "***REDACTED:SLACK_TOKEN***"},
	{ID: "stripe_secret", Pattern: `\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b`, Replacement: "***REDACTED:STRIPE_SECRET***", HighConfidence: true},
	{ID: "jwt", Pattern: `\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b`, Replacement: "***REDACTED:JWT***"},
	{ID: "private_key_block", Pattern: `-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`, Replacement: "***REDACTED:PRIVATE_KEY_BLOCK***", HighConfidence: true},
	{ID: "generic_bearer", Pattern: `(?i)bearer\s+[A-Za-z0-9_\-\.=]{20,}`, Replacement: "Bearer ***REDACTED:BEARER***"},
	{ID: "env_dotfile", Pattern: `(?m)^[A-Z][A-Z0-9_]{2,}=(?:["'][^"'\n]{8,}["']|[^\s"'#\n]{8,})`, Replacement: "***REDACTED:ENV_VAR***"},
}

var TrustedLLMHosts = map[string]struct{}{
	"api.anthropic.com":                 {},
	"api.openai.com":                    {},
	"generativelanguage.googleapis.com": {},
	"api.x.ai":                          {},
	"api.deepseek.com":                  {},
	"api.mistral.ai":                    {},
	"api.groq.com":                      {},
	"openrouter.ai":                     {},
}
