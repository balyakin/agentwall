# Reddit launch draft

I built **AgentWall**, a local network firewall for AI coding agents.

It runs as a proxy in front of tools like Claude Code, Aider, OpenCode, Codex CLI, etc.

Main features:

- blocks known telemetry endpoints by default
- redacts keys/tokens before request egress
- response guard for incoming secret leaks
- JSONL audit log
- budget control (`--budget`)
- CI gate (`--fail-on-blocked`)

Quick start:

```sh
curl -fsSL https://raw.githubusercontent.com/balyakin/agentwall/main/scripts/install.sh | sh
agentwall run -- claude
```

Repo: https://github.com/balyakin
