package doctor

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/balyakin/agentwall/internal/config"
)

type Check struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
}

type Report struct {
	Checks []Check `json:"checks"`
}

func Run(cfg config.Config) Report {
	checks := []Check{
		checkCA(),
		checkLogPath(cfg.Log.Path),
		checkPort(cfg.Port),
		checkEnvCollisions(),
	}
	return Report{Checks: checks}
}

func (r Report) HasFailures() bool {
	for _, c := range r.Checks {
		if c.Status == "fail" {
			return true
		}
	}
	return false
}

func (r Report) RenderJSON() string {
	raw, _ := json.MarshalIndent(r, "", "  ")
	return string(raw)
}

func (r Report) RenderText() string {
	var b strings.Builder
	b.WriteString("AgentWall doctor\n")
	b.WriteString("─────────────────────────────────────────────────────────────\n")
	for _, c := range r.Checks {
		icon := "✓"
		if c.Status == "warn" {
			icon = "⚠"
		}
		if c.Status == "fail" {
			icon = "✗"
		}
		b.WriteString(fmt.Sprintf("%s %s: %s\n", icon, c.Name, c.Message))
		if c.Fix != "" {
			b.WriteString("  fix: " + c.Fix + "\n")
		}
	}
	return b.String()
}

func checkCA() Check {
	appDir, err := config.AppDir()
	if err != nil {
		return Check{Name: "ca", Status: "fail", Message: err.Error()}
	}
	cert := filepath.Join(appDir, "ca.pem")
	key := filepath.Join(appDir, "ca.key")
	if _, err := os.Stat(cert); err != nil {
		return Check{Name: "ca", Status: "fail", Message: "CA certificate missing", Fix: "run: agentwall ca path && agentwall run -- <agent>"}
	}
	if _, err := os.Stat(key); err != nil {
		return Check{Name: "ca", Status: "fail", Message: "CA private key missing", Fix: "delete ~/.agentwall/ca* and rerun agentwall"}
	}
	return Check{Name: "ca", Status: "ok", Message: cert}
}

func checkLogPath(path string) Check {
	if path == "" {
		return Check{Name: "log", Status: "fail", Message: "log path is empty", Fix: "set log.path in config"}
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return Check{Name: "log", Status: "fail", Message: err.Error(), Fix: "set AGENTWALL_LOG to writable path"}
	}
	f, err := os.OpenFile(filepath.Join(dir, ".doctor-write-test"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		return Check{Name: "log", Status: "fail", Message: "log directory not writable", Fix: "chmod/chown log directory"}
	}
	_ = f.Close()
	_ = os.Remove(filepath.Join(dir, ".doctor-write-test"))
	return Check{Name: "log", Status: "ok", Message: path}
}

func checkPort(port int) Check {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return Check{Name: "proxy_port", Status: "fail", Message: "port is busy", Fix: fmt.Sprintf("set --port to another value (current %d)", port)}
	}
	_ = ln.Close()
	return Check{Name: "proxy_port", Status: "ok", Message: addr}
}

func checkEnvCollisions() Check {
	httpProxy := os.Getenv("HTTP_PROXY")
	httpsProxy := os.Getenv("HTTPS_PROXY")
	allProxy := os.Getenv("ALL_PROXY")
	if httpProxy == "" && httpsProxy == "" && allProxy == "" {
		return Check{Name: "env", Status: "ok", Message: "no conflicting proxy variables"}
	}
	return Check{
		Name:    "env",
		Status:  "warn",
		Message: "pre-existing proxy variables detected",
		Fix:     "agentwall run overrides child env automatically",
	}
}
