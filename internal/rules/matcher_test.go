package rules

import "testing"

func TestMatchHostSemantics(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		host    string
		want    bool
	}{
		{name: "exact match", pattern: "example.com", host: "example.com", want: true},
		{name: "exact mismatch subdomain", pattern: "example.com", host: "a.example.com", want: false},
		{name: "one level wildcard", pattern: "*.example.com", host: "a.example.com", want: true},
		{name: "one level wildcard no root", pattern: "*.example.com", host: "example.com", want: false},
		{name: "one level wildcard too deep", pattern: "*.example.com", host: "a.b.example.com", want: false},
		{name: "multi level includes root", pattern: "**.example.com", host: "example.com", want: true},
		{name: "multi level one subdomain", pattern: "**.example.com", host: "a.example.com", want: true},
		{name: "multi level deep", pattern: "**.example.com", host: "a.b.example.com", want: true},
		{name: "case insensitive", pattern: "EXAMPLE.COM", host: "example.com", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MatchHost(tt.pattern, tt.host); got != tt.want {
				t.Fatalf("MatchHost(%q, %q) = %v, want %v", tt.pattern, tt.host, got, tt.want)
			}
		})
	}
}

func TestMatchPath(t *testing.T) {
	if !MatchPath("/v1/*", "/v1/messages") {
		t.Fatalf("expected path glob to match")
	}
	if MatchPath("/v1/*", "/V1/messages") {
		t.Fatalf("path matching must be case-sensitive")
	}
}
