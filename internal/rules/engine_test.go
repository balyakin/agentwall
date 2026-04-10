package rules

import "testing"

func TestEnginePriorityBlockOverAllow(t *testing.T) {
	engine, err := New("balanced", []Rule{
		{ID: "allow-host", Action: ActionAllow, Host: "api.anthropic.com", Source: "user"},
		{ID: "block-path", Action: ActionBlock, Host: "api.anthropic.com", Path: "/v1/messages", Source: "user"},
	})
	if err != nil {
		t.Fatal(err)
	}
	d := engine.Decide(Request{Method: "POST", Host: "api.anthropic.com", Path: "/v1/messages"})
	if d.Action != ActionBlock {
		t.Fatalf("expected block, got %s", d.Action)
	}
	if d.MatchedRuleID != "block-path" {
		t.Fatalf("expected block-path rule, got %s", d.MatchedRuleID)
	}
}

func TestEngineStrictDefaultDeny(t *testing.T) {
	engine, err := New("strict", nil)
	if err != nil {
		t.Fatal(err)
	}
	d := engine.Decide(Request{Method: "GET", Host: "unknown.example", Path: "/"})
	if d.Action != ActionBlock || d.DecisionSource != "default" {
		t.Fatalf("expected strict default block, got action=%s source=%s", d.Action, d.DecisionSource)
	}
}

func TestEngineStrictAllowsUserHostForConnect(t *testing.T) {
	engine, err := New("strict", []Rule{{ID: "allow-custom", Action: ActionAllow, Host: "custom-llm.example.com", Source: "user"}})
	if err != nil {
		t.Fatal(err)
	}
	d := engine.Decide(Request{Method: "CONNECT", Host: "custom-llm.example.com:443", Path: ""})
	if d.Action != ActionAllow {
		t.Fatalf("expected allow for user strict rule, got %s", d.Action)
	}
	if d.MatchedRuleID != "allow-custom" {
		t.Fatalf("unexpected rule id: %s", d.MatchedRuleID)
	}
}

func TestEngineUserAllowOverridesBuiltinBlock(t *testing.T) {
	engine, err := New("balanced", []Rule{{ID: "allow-statsig", Action: ActionAllow, Host: "statsig.anthropic.com", Source: "user"}})
	if err != nil {
		t.Fatal(err)
	}
	d := engine.Decide(Request{Method: "POST", Host: "statsig.anthropic.com", Path: "/v1/rgstr"})
	if d.Action != ActionAllow {
		t.Fatalf("expected user allow to override builtin block, got %s", d.Action)
	}
	if d.DecisionSource != "user" || d.MatchedRuleID != "allow-statsig" {
		t.Fatalf("expected user rule decision, got source=%s rule=%s", d.DecisionSource, d.MatchedRuleID)
	}
}
