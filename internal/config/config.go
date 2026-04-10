package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	DefaultPort = 8723
)

type Config struct {
	Version          int              `yaml:"version"`
	Mode             string           `yaml:"mode"`
	Port             int              `yaml:"port"`
	Proxy            ProxyConfig      `yaml:"proxy"`
	Log              LogConfig        `yaml:"log"`
	UI               UIConfig         `yaml:"ui"`
	Sanitizers       SanitizersConfig `yaml:"sanitizers"`
	ResponseSanitize ResponseConfig   `yaml:"response_sanitize"`
	Budget           BudgetConfig     `yaml:"budget"`
	EnvGuard         EnvGuardConfig   `yaml:"env_guard"`
	Rules            []RuleConfig     `yaml:"rules"`
	FailOnBlocked    bool             `yaml:"fail_on_blocked"`
	Replay           string           `yaml:"replay"`
	SaveSession      string           `yaml:"save_session"`
	UpstreamProxy    string           `yaml:"upstream_proxy"`
	Extra            map[string]any   `yaml:",inline"`
}

type ProxyConfig struct {
	Upstream string `yaml:"upstream"`
}

type LogConfig struct {
	Path          string `yaml:"path"`
	MaxSizeMB     int    `yaml:"max_size_mb"`
	Rotate        bool   `yaml:"rotate"`
	MaxBackups    int    `yaml:"max_backups"`
	MaxAgeDays    int    `yaml:"max_age_days"`
	Compress      bool   `yaml:"compress"`
	DecisionTrace bool   `yaml:"decision_trace"`
}

type UIConfig struct {
	Color string `yaml:"color"`
	Level string `yaml:"level"`
}

type SanitizersConfig struct {
	Enabled   bool          `yaml:"enabled"`
	MaxBodyKB int           `yaml:"max_body_kb"`
	Custom    []RulePattern `yaml:"custom"`
}

type RulePattern struct {
	ID          string `yaml:"id"`
	Pattern     string `yaml:"pattern"`
	Replacement string `yaml:"replacement"`
}

type ResponseConfig struct {
	Mode string `yaml:"mode"`
}

type BudgetConfig struct {
	USD         float64 `yaml:"usd"`
	OnExceed    string  `yaml:"on_exceed"`
	PriceSource string  `yaml:"price_source"`
}

type EnvGuardConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Discover  []string `yaml:"discover"`
	MaxFileKB int      `yaml:"max_file_kb"`
}

type RuleConfig struct {
	ID          string `yaml:"id"`
	Action      string `yaml:"action"`
	Host        string `yaml:"host"`
	Path        string `yaml:"path"`
	Method      string `yaml:"method"`
	BodyRegex   string `yaml:"body_regex"`
	HeaderRegex string `yaml:"header_regex"`
}

type mergePresence struct {
	logRotate         bool
	logCompress       bool
	logDecisionTrace  bool
	sanitizersEnabled bool
	envGuardEnabled   bool
	failOnBlocked     bool
}

func AppDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".agentwall"), nil
}

func Default() Config {
	dir := ".agentwall"
	if resolved, err := AppDir(); err == nil {
		dir = resolved
	}
	return Config{
		Version: 1,
		Mode:    "balanced",
		Port:    DefaultPort,
		Log: LogConfig{
			Path:          filepath.Join(dir, "log.jsonl"),
			MaxSizeMB:     100,
			Rotate:        true,
			MaxBackups:    5,
			MaxAgeDays:    14,
			Compress:      true,
			DecisionTrace: true,
		},
		UI: UIConfig{Color: "auto", Level: "info"},
		Sanitizers: SanitizersConfig{
			Enabled:   true,
			MaxBodyKB: 2048,
		},
		ResponseSanitize: ResponseConfig{Mode: ""},
		Budget: BudgetConfig{
			USD:         0,
			OnExceed:    "block",
			PriceSource: "builtin",
		},
		EnvGuard: EnvGuardConfig{
			Enabled:   true,
			Discover:  []string{".env", ".env.local", ".env.*.local"},
			MaxFileKB: 256,
		},
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	appDir, err := AppDir()
	if err != nil {
		return cfg, err
	}
	if err := os.MkdirAll(appDir, 0o700); err != nil {
		return cfg, err
	}

	globalPath := filepath.Join(appDir, "config.yaml")
	if path != "" {
		globalPath = path
	}

	if err := mergeFile(&cfg, globalPath); err != nil {
		return cfg, err
	}

	projectPath, err := FindProjectConfig(".")
	if err != nil {
		return cfg, err
	}
	if projectPath != "" {
		if err := mergeFile(&cfg, projectPath); err != nil {
			return cfg, err
		}
	}

	applyEnvOverrides(&cfg)
	cfg.normalize()
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (c *Config) normalize() {
	c.Mode = strings.ToLower(strings.TrimSpace(c.Mode))
	if c.Mode == "" {
		c.Mode = "balanced"
	}
	if c.Port == 0 {
		c.Port = DefaultPort
	}
	if c.Proxy.Upstream != "" {
		c.UpstreamProxy = c.Proxy.Upstream
	}
	if c.Log.Path == "" {
		if dir, err := AppDir(); err == nil {
			c.Log.Path = filepath.Join(dir, "log.jsonl")
		}
	}
	c.Log.Path = expandUserPath(c.Log.Path)
	c.Replay = expandUserPath(c.Replay)
	c.SaveSession = expandUserPath(c.SaveSession)
	c.ResponseSanitize.Mode = strings.ToLower(strings.TrimSpace(c.ResponseSanitize.Mode))
	if c.ResponseSanitize.Mode != "" && !isValidResponseMode(c.ResponseSanitize.Mode) {
		c.ResponseSanitize.Mode = ""
	}
	if c.ResponseSanitize.Mode == "" {
		switch c.Mode {
		case "loose":
			c.ResponseSanitize.Mode = "detect"
		case "strict":
			c.ResponseSanitize.Mode = "block"
		default:
			c.ResponseSanitize.Mode = "sanitize"
		}
	}
	if c.Sanitizers.MaxBodyKB <= 0 {
		c.Sanitizers.MaxBodyKB = 2048
	}
}

func (c Config) Validate() error {
	switch c.Mode {
	case "loose", "balanced", "strict":
	default:
		return fmt.Errorf("unsupported mode: %s", c.Mode)
	}
	if !isValidResponseMode(c.ResponseSanitize.Mode) {
		return fmt.Errorf("invalid response_sanitize.mode: %s", c.ResponseSanitize.Mode)
	}
	return nil
}

func isValidResponseMode(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "off", "detect", "sanitize", "block":
		return true
	default:
		return false
	}
}

func expandUserPath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return ""
	}
	if trimmed == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return trimmed
		}
		return home
	}
	if strings.HasPrefix(trimmed, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return trimmed
		}
		return filepath.Join(home, strings.TrimPrefix(trimmed, "~/"))
	}
	return trimmed
}

func mergeFile(cfg *Config, path string) error {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var overlay Config
	if err := yaml.Unmarshal(raw, &overlay); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	var node yaml.Node
	if err := yaml.Unmarshal(raw, &node); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	presence := detectMergePresence(&node)
	merge(cfg, overlay, presence)
	return nil
}

func merge(dst *Config, src Config, presence mergePresence) {
	if src.Version != 0 {
		dst.Version = src.Version
	}
	if src.Mode != "" {
		dst.Mode = src.Mode
	}
	if src.Port != 0 {
		dst.Port = src.Port
	}
	if src.Proxy.Upstream != "" {
		dst.Proxy.Upstream = src.Proxy.Upstream
		dst.UpstreamProxy = src.Proxy.Upstream
	}
	if src.Log.Path != "" {
		dst.Log.Path = src.Log.Path
	}
	if src.Log.MaxSizeMB != 0 {
		dst.Log.MaxSizeMB = src.Log.MaxSizeMB
	}
	if src.Log.MaxBackups != 0 {
		dst.Log.MaxBackups = src.Log.MaxBackups
	}
	if src.Log.MaxAgeDays != 0 {
		dst.Log.MaxAgeDays = src.Log.MaxAgeDays
	}
	if presence.logRotate {
		dst.Log.Rotate = src.Log.Rotate
	}
	if presence.logCompress {
		dst.Log.Compress = src.Log.Compress
	}
	if presence.logDecisionTrace {
		dst.Log.DecisionTrace = src.Log.DecisionTrace
	}

	if src.UI.Color != "" {
		dst.UI.Color = src.UI.Color
	}
	if src.UI.Level != "" {
		dst.UI.Level = src.UI.Level
	}

	if src.Sanitizers.MaxBodyKB != 0 {
		dst.Sanitizers.MaxBodyKB = src.Sanitizers.MaxBodyKB
	}
	if len(src.Sanitizers.Custom) > 0 {
		dst.Sanitizers.Custom = append(dst.Sanitizers.Custom, src.Sanitizers.Custom...)
	}
	if presence.sanitizersEnabled {
		dst.Sanitizers.Enabled = src.Sanitizers.Enabled
	}

	if src.ResponseSanitize.Mode != "" {
		dst.ResponseSanitize.Mode = src.ResponseSanitize.Mode
	}

	if src.Budget.USD != 0 {
		dst.Budget.USD = src.Budget.USD
	}
	if src.Budget.OnExceed != "" {
		dst.Budget.OnExceed = src.Budget.OnExceed
	}
	if src.Budget.PriceSource != "" {
		dst.Budget.PriceSource = src.Budget.PriceSource
	}

	if presence.envGuardEnabled {
		dst.EnvGuard.Enabled = src.EnvGuard.Enabled
	}
	if src.EnvGuard.MaxFileKB != 0 {
		dst.EnvGuard.MaxFileKB = src.EnvGuard.MaxFileKB
	}
	if len(src.EnvGuard.Discover) > 0 {
		dst.EnvGuard.Discover = append([]string(nil), src.EnvGuard.Discover...)
	}

	if presence.failOnBlocked {
		dst.FailOnBlocked = src.FailOnBlocked
	}
	if src.Replay != "" {
		dst.Replay = src.Replay
	}
	if src.SaveSession != "" {
		dst.SaveSession = src.SaveSession
	}
	if src.UpstreamProxy != "" {
		dst.UpstreamProxy = src.UpstreamProxy
	}
	if len(src.Rules) > 0 {
		dst.Rules = append(dst.Rules, src.Rules...)
	}
}

func detectMergePresence(node *yaml.Node) mergePresence {
	return mergePresence{
		logRotate:         yamlPathExists(node, "log", "rotate"),
		logCompress:       yamlPathExists(node, "log", "compress"),
		logDecisionTrace:  yamlPathExists(node, "log", "decision_trace"),
		sanitizersEnabled: yamlPathExists(node, "sanitizers", "enabled"),
		envGuardEnabled:   yamlPathExists(node, "env_guard", "enabled"),
		failOnBlocked:     yamlPathExists(node, "fail_on_blocked"),
	}
}

func yamlPathExists(node *yaml.Node, path ...string) bool {
	if node == nil || len(path) == 0 {
		return false
	}
	cur := node
	if cur.Kind == yaml.DocumentNode && len(cur.Content) > 0 {
		cur = cur.Content[0]
	}
	for i, key := range path {
		if cur.Kind != yaml.MappingNode {
			return false
		}
		found := false
		for j := 0; j+1 < len(cur.Content); j += 2 {
			if cur.Content[j].Value == key {
				cur = cur.Content[j+1]
				found = true
				break
			}
		}
		if !found {
			return false
		}
		if i == len(path)-1 {
			return true
		}
	}
	return false
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("AGENTWALL_MODE"); v != "" {
		cfg.Mode = v
	}
	if v := os.Getenv("AGENTWALL_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.Port = p
		}
	}
	if v := os.Getenv("AGENTWALL_LOG"); v != "" {
		cfg.Log.Path = v
	}
	if v := os.Getenv("AGENTWALL_UPSTREAM_PROXY"); v != "" {
		cfg.UpstreamProxy = v
	}
	if v := os.Getenv("AGENTWALL_NO_SANITIZE"); v == "1" || strings.EqualFold(v, "true") {
		cfg.Sanitizers.Enabled = false
	}
	if v := os.Getenv("AGENTWALL_RESPONSE_SANITIZE"); v != "" {
		cfg.ResponseSanitize.Mode = v
	}
	if v := os.Getenv("AGENTWALL_BUDGET_USD"); v != "" {
		if usd, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.Budget.USD = usd
		}
	}
	if v := os.Getenv("AGENTWALL_FAIL_ON_BLOCKED"); v == "1" || strings.EqualFold(v, "true") {
		cfg.FailOnBlocked = true
	}
	if v := os.Getenv("AGENTWALL_REPLAY"); v != "" {
		cfg.Replay = v
	}
	if v := os.Getenv("AGENTWALL_SAVE_SESSION"); v != "" {
		cfg.SaveSession = v
	}
	if v := os.Getenv("AGENTWALL_ENV_GUARD"); v != "" {
		cfg.EnvGuard.Enabled = v == "1" || strings.EqualFold(v, "true")
	}
}

func FindProjectConfig(start string) (string, error) {
	abs, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		candidate := filepath.Join(abs, ".agentwall.yaml")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return "", nil
		}
		abs = parent
	}
}

func RenderDefaultYAML() string {
	return `version: 1
mode: balanced
port: 8723
proxy:
  upstream: ""
log:
  path: ~/.agentwall/log.jsonl
  max_size_mb: 100
  rotate: true
  max_backups: 5
  max_age_days: 14
  compress: true
  decision_trace: true
ui:
  color: auto
  level: info
sanitizers:
  enabled: true
  max_body_kb: 2048
  custom: []
response_sanitize:
  mode: ""
budget:
  usd: 0
  on_exceed: block
  price_source: builtin
env_guard:
  enabled: true
  discover:
    - .env
    - .env.local
    - .env.*.local
  max_file_kb: 256
rules: []
`
}
