package ui

import (
	"fmt"
	"time"
)

func (w *Inline) PrintSummary(s Summary, logPath string) {
	if w.quiet {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	fmt.Fprintln(w.out, "  ─────────────────────────────────────────────────────────────")
	fmt.Fprintf(w.out, "  ▲ AgentWall summary    duration: %s\n", s.Duration.Round(time.Second))
	fmt.Fprintln(w.out, "  ─────────────────────────────────────────────────────────────")
	fmt.Fprintf(w.out, "   Requests      %5d\n", s.Requests)
	fmt.Fprintf(w.out, "   Allowed       %5d\n", s.Allowed)
	fmt.Fprintf(w.out, "   Blocked       %5d\n", s.Blocked)
	fmt.Fprintf(w.out, "   Sanitized     %5d\n", s.Sanitized)
	fmt.Fprintf(w.out, "   Errors        %5d\n", s.Errors)
	if s.BudgetUSD > 0 {
		fmt.Fprintf(w.out, "   Spent         $%0.2f (budget: $%0.2f)\n", s.SpentUSD, s.BudgetUSD)
	}
	if len(s.TopHosts) > 0 {
		fmt.Fprintln(w.out, "   Top hosts:")
		for i := 0; i < len(s.TopHosts) && i < 3; i++ {
			h := s.TopHosts[i]
			fmt.Fprintf(w.out, "     %-28s %4d\n", h.Host, h.Count)
		}
	}
	if len(s.TopBlocked) > 0 {
		fmt.Fprintln(w.out, "   Top blocked:")
		for i := 0; i < len(s.TopBlocked) && i < 3; i++ {
			h := s.TopBlocked[i]
			fmt.Fprintf(w.out, "     %-28s %4d\n", h.Host, h.Count)
		}
	}
	fmt.Fprintln(w.out, "  ─────────────────────────────────────────────────────────────")
	if logPath != "" {
		fmt.Fprintf(w.out, "   Full log: %s\n", logPath)
	}
}
