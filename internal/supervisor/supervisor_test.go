package supervisor

import (
	"slices"
	"strings"
	"testing"
)

func TestBuildEnvInjectsProxyAndCA(t *testing.T) {
	r := &Runner{ProxyAddr: "127.0.0.1:8723", CAPath: "/tmp/ca.pem"}
	env := r.BuildEnv([]string{"NO_PROXY=example.com,localhost,10.0.0.0/8,.local"})
	envMap := map[string]string{}
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if ok {
			envMap[k] = v
		}
	}
	if envMap["HTTPS_PROXY"] != "http://127.0.0.1:8723" {
		t.Fatalf("missing HTTPS_PROXY")
	}
	if envMap["NODE_EXTRA_CA_CERTS"] != "/tmp/ca.pem" {
		t.Fatalf("missing NODE_EXTRA_CA_CERTS")
	}
	np := strings.Split(envMap["NO_PROXY"], ",")
	if !slices.Contains(np, "127.0.0.1") || !slices.Contains(np, "localhost") || !slices.Contains(np, "::1") {
		t.Fatalf("expected NO_PROXY to contain localhost addresses, got %s", envMap["NO_PROXY"])
	}
	if slices.Contains(np, "example.com") {
		t.Fatalf("expected external NO_PROXY entries to be removed, got %s", envMap["NO_PROXY"])
	}
	if !slices.Contains(np, "10.0.0.0/8") || !slices.Contains(np, ".local") {
		t.Fatalf("expected private/local NO_PROXY entries to be kept, got %s", envMap["NO_PROXY"])
	}
}
