package rules

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

type Action string

const (
	ActionAllow    Action = "allow"
	ActionBlock    Action = "block"
	ActionSanitize Action = "sanitize"
	ActionDeny     Action = "deny"
)

type Rule struct {
	ID          string
	Action      Action
	Host        string
	Path        string
	Method      string
	BodyRegex   string
	HeaderRegex string
	Source      string

	bodyRE   *regexp.Regexp
	headerRE *regexp.Regexp
}

type Request struct {
	Method   string
	Host     string
	Path     string
	RawQuery string
	Headers  http.Header
	Body     []byte
}

type Decision struct {
	Action         Action   `json:"action"`
	DecisionSource string   `json:"decision_source"`
	MatchedRuleID  string   `json:"matched_rule_id,omitempty"`
	MatchedFields  []string `json:"matched_fields,omitempty"`
	Reason         string   `json:"reason,omitempty"`
}

type Engine struct {
	mode          string
	defaultPolicy Action
	rules         []Rule
	builtinRules  []Rule
}

func New(mode string, userRules []Rule) (*Engine, error) {
	e := &Engine{mode: mode, defaultPolicy: ActionAllow}
	switch strings.ToLower(mode) {
	case "strict":
		e.defaultPolicy = ActionDeny
	case "balanced", "loose", "":
		e.defaultPolicy = ActionAllow
	default:
		return nil, fmt.Errorf("unsupported mode: %s", mode)
	}

	builtin, err := buildBuiltinRules(strings.ToLower(mode))
	if err != nil {
		return nil, err
	}
	for i := range userRules {
		if userRules[i].Source == "" {
			userRules[i].Source = "user"
		}
	}
	compiledUser, err := compileRules(userRules)
	if err != nil {
		return nil, err
	}
	compiledBuiltin, err := compileRules(builtin)
	if err != nil {
		return nil, err
	}
	e.rules = compiledUser
	e.builtinRules = compiledBuiltin
	return e, nil
}

func compileRules(rules []Rule) ([]Rule, error) {
	out := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if r.ID == "" {
			r.ID = "anonymous"
		}
		if r.Source == "" {
			r.Source = "builtin"
		}
		if r.BodyRegex != "" {
			re, err := regexp.Compile(r.BodyRegex)
			if err != nil {
				return nil, fmt.Errorf("compile body regex for %s: %w", r.ID, err)
			}
			r.bodyRE = re
		}
		if r.HeaderRegex != "" {
			re, err := regexp.Compile(r.HeaderRegex)
			if err != nil {
				return nil, fmt.Errorf("compile header regex for %s: %w", r.ID, err)
			}
			r.headerRE = re
		}
		out = append(out, r)
	}
	return out, nil
}

func buildBuiltinRules(mode string) ([]Rule, error) {
	out := make([]Rule, 0)
	if mode == "balanced" || mode == "strict" {
		for i, pattern := range BuiltinTelemetryBlocklist {
			out = append(out, Rule{
				ID:     fmt.Sprintf("telemetry.%d", i+1),
				Action: ActionBlock,
				Host:   pattern,
				Source: "builtin",
			})
		}
	}
	if mode == "strict" {
		for i, pattern := range BuiltinStrictAllowlist {
			out = append(out, Rule{
				ID:     fmt.Sprintf("strict.allow.%d", i+1),
				Action: ActionAllow,
				Host:   pattern,
				Source: "builtin",
			})
		}
	}
	return out, nil
}

func (e *Engine) Decide(req Request) Decision {
	userMatches := make([]Rule, 0)
	builtinMatches := make([]Rule, 0)
	for _, r := range e.rules {
		if matchesRule(r, req) {
			userMatches = append(userMatches, r)
		}
	}
	for _, r := range e.builtinRules {
		if matchesRule(r, req) {
			builtinMatches = append(builtinMatches, r)
		}
	}
	matches := builtinMatches
	if len(userMatches) > 0 {
		matches = userMatches
	}

	if len(matches) == 0 {
		if e.defaultPolicy == ActionDeny {
			return Decision{Action: ActionBlock, DecisionSource: "default", Reason: "strict default deny"}
		}
		return Decision{Action: ActionAllow, DecisionSource: "default", Reason: "default allow"}
	}
	winner := matches[0]
	for i := 1; i < len(matches); i++ {
		if actionWeight(matches[i].Action) > actionWeight(winner.Action) {
			winner = matches[i]
		}
	}
	fields := matchedFields(winner, req)
	return Decision{
		Action:         winner.Action,
		DecisionSource: winner.Source,
		MatchedRuleID:  winner.ID,
		MatchedFields:  fields,
	}
}

func actionWeight(action Action) int {
	switch action {
	case ActionBlock:
		return 4
	case ActionSanitize:
		return 3
	case ActionAllow:
		return 2
	default:
		return 1
	}
}

func matchesRule(rule Rule, req Request) bool {
	if rule.Host != "" && !MatchHost(rule.Host, req.Host) {
		return false
	}
	if rule.Path != "" && !MatchPath(rule.Path, req.Path) {
		return false
	}
	if rule.Method != "" && !strings.EqualFold(rule.Method, req.Method) {
		return false
	}
	if rule.bodyRE != nil && !rule.bodyRE.Match(req.Body) {
		return false
	}
	if rule.headerRE != nil {
		headers := headersToString(req.Headers)
		if !rule.headerRE.MatchString(headers) {
			return false
		}
	}
	return true
}

func matchedFields(rule Rule, req Request) []string {
	fields := make([]string, 0, 5)
	if rule.Host != "" && MatchHost(rule.Host, req.Host) {
		fields = append(fields, "host")
	}
	if rule.Path != "" && MatchPath(rule.Path, req.Path) {
		fields = append(fields, "path")
	}
	if rule.Method != "" && strings.EqualFold(rule.Method, req.Method) {
		fields = append(fields, "method")
	}
	if rule.bodyRE != nil && rule.bodyRE.Match(req.Body) {
		fields = append(fields, "body_regex")
	}
	if rule.headerRE != nil && rule.headerRE.MatchString(headersToString(req.Headers)) {
		fields = append(fields, "header_regex")
	}
	return fields
}

func headersToString(h http.Header) string {
	if len(h) == 0 {
		return ""
	}
	var b strings.Builder
	for k, values := range h {
		for _, v := range values {
			b.WriteString(k)
			b.WriteByte(':')
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	return b.String()
}
