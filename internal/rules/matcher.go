package rules

import (
	"net"
	"path"
	"strings"
)

func NormalizeHost(hostport string) string {
	host := strings.TrimSpace(strings.ToLower(hostport))
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = strings.ToLower(h)
	}
	host = strings.TrimSuffix(host, ".")
	return host
}

func MatchHost(pattern, host string) bool {
	pattern = strings.TrimSpace(strings.ToLower(pattern))
	host = NormalizeHost(host)
	if pattern == "" || pattern == "*" || pattern == "**" {
		return true
	}

	if strings.HasPrefix(pattern, "**.") {
		base := strings.TrimPrefix(pattern, "**.")
		if host == base {
			return true
		}
		return strings.HasSuffix(host, "."+base)
	}

	if strings.HasPrefix(pattern, "*.") {
		base := strings.TrimPrefix(pattern, "*.")
		suffix := "." + base
		if !strings.HasSuffix(host, suffix) {
			return false
		}
		left := strings.TrimSuffix(host, suffix)
		if left == "" {
			return false
		}
		return !strings.Contains(left, ".")
	}

	return host == pattern
}

func MatchPath(pattern, reqPath string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	ok, err := path.Match(pattern, reqPath)
	if err != nil {
		return false
	}
	return ok
}
