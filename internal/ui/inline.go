package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
)

type Event struct {
	TS             time.Time `json:"ts"`
	Action         string    `json:"action"`
	Method         string    `json:"method,omitempty"`
	Host           string    `json:"host,omitempty"`
	Path           string    `json:"path,omitempty"`
	Rule           string    `json:"rule,omitempty"`
	DecisionSource string    `json:"decision_source,omitempty"`
	MatchedRuleID  string    `json:"matched_rule_id,omitempty"`
	MatchedFields  []string  `json:"matched_fields,omitempty"`
	Mode           string    `json:"mode,omitempty"`
	BytesIn        int64     `json:"bytes_in,omitempty"`
	BytesOut       int64     `json:"bytes_out,omitempty"`
	Sanitizers     []string  `json:"sanitizers,omitempty"`
	Direction      string    `json:"direction,omitempty"`
	Reason         string    `json:"reason,omitempty"`
	Provider       string    `json:"provider,omitempty"`
	Model          string    `json:"model,omitempty"`
	SessionSpent   float64   `json:"session_spent_usd,omitempty"`
	BudgetUSD      float64   `json:"budget_usd,omitempty"`
	TLSMode        string    `json:"tls_mode,omitempty"`
}

type Summary struct {
	Duration        time.Duration
	Requests        int
	Allowed         int
	Blocked         int
	Sanitized       int
	Errors          int
	SecretsRedacted int
	SpentUSD        float64
	BudgetUSD       float64
	TopHosts        []HostCounter
	TopBlocked      []HostCounter
}

type HostCounter struct {
	Host  string
	Count int
}

type Inline struct {
	out         io.Writer
	noColor     bool
	jsonOut     bool
	quiet       bool
	eventsMuted bool
	mu          sync.Mutex
}

func NewInline(out io.Writer, noColor, jsonOut, quiet bool) *Inline {
	return &Inline{out: out, noColor: noColor, jsonOut: jsonOut, quiet: quiet}
}

func (w *Inline) SetEventsMuted(muted bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.eventsMuted = muted
}

func (w *Inline) Banner(version, mode, proxyAddr, child string) {
	if w.quiet {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	banner := "▲ AgentWall"
	if !w.noColor {
		banner = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#4FD1C5")).Render("▲ AgentWall")
	}
	fmt.Fprintf(w.out, "\n  %s  %s   mode: %s   proxy: %s\n", banner, version, mode, proxyAddr)
	fmt.Fprintln(w.out, "  ─────────────────────────────────────────────────────────────")
	if child != "" {
		fmt.Fprintf(w.out, "  ▸ spawning: %s\n", child)
	}
	fmt.Fprintln(w.out, "  ▸ child env: HTTPS_PROXY, HTTP_PROXY, NODE_EXTRA_CA_CERTS injected")
	fmt.Fprintln(w.out, "  ─────────────────────────────────────────────────────────────")
}

func (w *Inline) Print(e Event) {
	w.mu.Lock()
	eventsMuted := w.eventsMuted
	w.mu.Unlock()
	if w.quiet || eventsMuted {
		return
	}
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	if w.jsonOut {
		w.mu.Lock()
		defer w.mu.Unlock()
		raw, _ := json.Marshal(e)
		_, _ = fmt.Fprintln(w.out, string(raw))
		return
	}

	timeText := e.TS.Local().Format("15:04:05")
	action := strings.ToUpper(e.Action)
	symbol := "✓"
	color := lipgloss.Color("#7CFC9D")
	switch action {
	case "BLOCK":
		symbol = "✗"
		color = lipgloss.Color("#FF5F87")
	case "CLEAN", "R_CLEAN":
		symbol = "⚠"
		color = lipgloss.Color("#FFD866")
	case "ERROR":
		symbol = "!"
		color = lipgloss.Color("#FF5FFF")
	case "COST":
		symbol = "$"
		color = lipgloss.Color("#6EC1FF")
	case "PASS":
		symbol = "⚠"
		color = lipgloss.Color("#FFC857")
	}
	label := fmt.Sprintf("%s %-7s", symbol, action)
	if !w.noColor {
		label = lipgloss.NewStyle().Bold(true).Foreground(color).Render(label)
	}
	line := fmt.Sprintf("  %s  %s  %-5s %-38s", timeText, label, e.Method, e.Host+e.Path)
	if e.Action == "cost" {
		line = fmt.Sprintf("  %s  %s  usage total                                 $%.2f / $%.2f", timeText, label, e.SessionSpent, e.BudgetUSD)
	}
	if e.Rule != "" {
		line += fmt.Sprintf(" rule: %s", e.Rule)
	}
	if len(e.Sanitizers) > 0 {
		line += fmt.Sprintf(" %d secrets redacted [%s]", len(e.Sanitizers), strings.Join(e.Sanitizers, ", "))
	}
	if e.Reason != "" && e.Action != "cost" {
		line += " " + e.Reason
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_, _ = fmt.Fprintln(w.out, line)
}
