package ui

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

type ExplainDecision string

const (
	ExplainAllowOnce ExplainDecision = "allow_once"
	ExplainAlways    ExplainDecision = "always"
	ExplainBlock     ExplainDecision = "block"
	ExplainSanitize  ExplainDecision = "sanitize"
)

type Explainer struct {
	in     *bufio.Reader
	out    io.Writer
	always map[string]ExplainDecision
}

func NewExplainer(in io.Reader, out io.Writer) *Explainer {
	return &Explainer{in: bufio.NewReader(in), out: out, always: map[string]ExplainDecision{}}
}

func (e *Explainer) Decide(host, line string) ExplainDecision {
	if d, ok := e.always[host]; ok {
		return d
	}
	fmt.Fprintf(e.out, "[explain] %s\n", line)
	fmt.Fprint(e.out, "Press Enter=allow once, a=always, b=block, s=sanitize: ")
	raw, _ := e.in.ReadString('\n')
	choice := strings.TrimSpace(strings.ToLower(raw))
	switch choice {
	case "a":
		e.always[host] = ExplainAllowOnce
		return ExplainAllowOnce
	case "b":
		return ExplainBlock
	case "s":
		return ExplainSanitize
	default:
		return ExplainAllowOnce
	}
}
