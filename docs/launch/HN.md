# Show HN draft

Title: **Show HN: AgentWall – a network firewall for AI coding agents**

AgentWall is a local, zero-config network firewall for CLI coding agents.

You run:

```sh
agentwall run -- claude
```

and AgentWall acts as a local HTTP/HTTPS proxy with policy enforcement.

What it does:

- blocks known telemetry hosts
- redacts API keys before they leave your machine
- logs every decision to JSONL for audit
- supports strict CI mode (`--fail-on-blocked`)
- can enforce spend budget (`--budget`)

It is intentionally agent-agnostic: if a CLI tool respects `HTTP_PROXY/HTTPS_PROXY`, it works.

No cloud dependencies, no SaaS reputation API, no mandatory web dashboard.

Looking for feedback on:

1. false-positive rate in balanced mode
2. additional telemetry endpoints we missed
3. strict mode allowlist defaults
