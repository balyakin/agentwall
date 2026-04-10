package supervisor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

type Result struct {
	ExitCode int
}

type Runner struct {
	ProxyAddr string
	CAPath    string
	ExtraEnv  map[string]string
}

func (r *Runner) BuildEnv(base []string) []string {
	env := map[string]string{}
	for _, kv := range base {
		k, v, ok := strings.Cut(kv, "=")
		if ok {
			env[k] = v
		}
	}
	proxyURL := "http://" + r.ProxyAddr
	env["HTTP_PROXY"] = proxyURL
	env["HTTPS_PROXY"] = proxyURL
	env["http_proxy"] = proxyURL
	env["https_proxy"] = proxyURL
	env["ALL_PROXY"] = proxyURL
	env["NODE_EXTRA_CA_CERTS"] = r.CAPath
	env["SSL_CERT_FILE"] = r.CAPath
	env["REQUESTS_CA_BUNDLE"] = r.CAPath
	env["CURL_CA_BUNDLE"] = r.CAPath

	for k, v := range r.ExtraEnv {
		env[k] = v
	}
	cleanupNoProxy(env)

	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}

func cleanupNoProxy(env map[string]string) {
	value := env["NO_PROXY"]
	if value == "" {
		value = env["no_proxy"]
	}
	parts := strings.Split(value, ",")
	ordered := make([]string, 0, len(parts)+3)
	seen := map[string]struct{}{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !allowedNoProxyEntry(p) {
			continue
		}
		key := strings.ToLower(p)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		ordered = append(ordered, p)
	}
	for _, local := range []string{"127.0.0.1", "localhost", "::1"} {
		key := strings.ToLower(local)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		ordered = append(ordered, local)
	}
	joined := strings.Join(ordered, ",")
	env["NO_PROXY"] = joined
	env["no_proxy"] = joined
}

func allowedNoProxyEntry(entry string) bool {
	normalized := strings.ToLower(strings.TrimSpace(entry))
	normalized = strings.Trim(normalized, "[]")
	if normalized == "localhost" || normalized == "127.0.0.1" || normalized == "::1" {
		return true
	}
	if strings.HasSuffix(normalized, ".local") || strings.HasSuffix(normalized, ".localhost") {
		return true
	}
	if ip := net.ParseIP(normalized); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	if _, network, err := net.ParseCIDR(normalized); err == nil {
		ip := network.IP
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	return false
}

func (r *Runner) Run(ctx context.Context, command []string) (Result, error) {
	if len(command) == 0 {
		return Result{}, errors.New("no child command provided")
	}
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = r.BuildEnv(os.Environ())

	if err := cmd.Start(); err != nil {
		return Result{}, err
	}

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go func() {
		for sig := range sigCh {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
		}
	}()

	err := cmd.Wait()
	close(sigCh)
	if err == nil {
		return Result{ExitCode: 0}, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		if status, ok := exit.Sys().(syscall.WaitStatus); ok {
			return Result{ExitCode: status.ExitStatus()}, nil
		}
		return Result{ExitCode: 1}, nil
	}
	return Result{}, fmt.Errorf("child wait failed: %w", err)
}

func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if status, ok := ee.Sys().(syscall.WaitStatus); ok {
			return status.ExitStatus()
		}
	}
	if code, conv := strconv.Atoi(err.Error()); conv == nil {
		return code
	}
	return 1
}
