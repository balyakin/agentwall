# AgentWall

**A zero-config network firewall for AI coding agents. See exactly where Claude Code, Aider, OpenCode and friends try to send your data, and stop them when they shouldn't.**

![Demo GIF placeholder](docs/assets/demo.gif "15-second terminal demo: run claude behind agentwall, telemetry blocked, secret redacted, summary shown")

[![CI](https://github.com/balyakin/agentwall/actions/workflows/ci.yml/badge.svg)](https://github.com/balyakin/agentwall/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/balyakin/agentwall)](https://github.com/balyakin/agentwall/releases)
[![Stars](https://img.shields.io/github/stars/balyakin/agentwall?style=social)](https://github.com/balyakin)
[![Discord](https://img.shields.io/badge/discord-agentwall-5865F2)](https://discord.gg/agentwall)

## Why?

Modern AI coding agents get full terminal + network capabilities. You trust them with your codebase, your shell, and often your production credentials.

Many of them also emit telemetry and may send unexpected requests in the background. Without packet-level visibility, you cannot easily answer a basic question: _what did my agent send, and where?_

AgentWall solves this with one static Go binary. No SDK hooks. No cloud dependency. No Node.js runtime. You run your agent through a local proxy and get real-time policy enforcement + audit trail.

## Quick start

```sh
curl -fsSL https://raw.githubusercontent.com/balyakin/agentwall/main/scripts/install.sh | sh
agentwall run -- claude
```

## What it does

- 🛡 Blocks 80+ known telemetry endpoints out of the box.
- 🔒 Redacts API keys, AWS creds, GitHub tokens before they leave your machine.
- 💸 Enforces per-session budget (`--budget`) to stop runaway agent spend.
- 🔁 Replays saved sessions (`--replay`) for free deterministic debugging.
- 👀 Shows you, in real time, exactly where your agent talks.
- 📜 Writes a structured audit log you can `grep`.
- ✅ Supports CI gate (`--fail-on-blocked`) for enterprise pipelines.
- 🧩 Works with any CLI agent that respects `HTTPS_PROXY`.
- 🪶 Single static binary. No Docker. No Node. No Python.

## Terminal output

```text
$ agentwall run -- claude

  ▲ AgentWall  v0.1.0   mode: balanced   proxy: 127.0.0.1:8723
  ─────────────────────────────────────────────────────────────
  ▸ spawning: claude
  ▸ child env: HTTPS_PROXY, NODE_EXTRA_CA_CERTS injected
  ─────────────────────────────────────────────────────────────

  12:04:07  ✓ ALLOW   POST  api.anthropic.com/v1/messages
  12:04:08  ✗ BLOCK   POST  statsig.anthropic.com/v1/rgstr  rule: telemetry.1
  12:04:09  ⚠ CLEAN   POST  api.anthropic.com/v1/messages   2 secrets redacted
  12:04:19  $ COST    usage total                           $1.42 / $5.00
```

## Modes

| Mode | Default policy | Telemetry blocklist | Sanitizers |
|---|---|---|---|
| `loose` | allow | off | on |
| `balanced` (default) | allow | on | on |
| `strict` | deny (allowlist only) | on | on |

## Compatibility

| Agent | Status |
|---|---|
| Claude Code | ✅ |
| Aider | ✅ |
| OpenCode | ✅ |
| Codex CLI | ✅ |
| Gemini CLI | ✅ |
| Continue CLI | ✅ |

| OS / arch | Status |
|---|---|
| linux/amd64 | ✅ |
| linux/arm64 | ✅ |
| darwin/amd64 | ✅ |
| darwin/arm64 | ✅ |
| windows/amd64 | ✅ |
| windows/arm64 | ✅ |

## How it compares

| | AgentWall | Sage | cc-gateway | Aegis |
|---|---|---|---|---|
| Works with any CLI agent | ✅ | ❌ (per-agent hooks) | ❌ (Claude Code only) | ❌ (SDK integration) |
| Network-layer interception | ✅ | ❌ (tool-call layer) | ✅ | ❌ |
| Single static binary | ✅ | ❌ (Node.js) | ❌ (Node.js) | ❌ (Docker) |
| Zero config | ✅ | ⚠ | ⚠ | ❌ |
| Secret redaction | ✅ | ❌ | ❌ | ⚠ |
| Offline by default | ✅ | ❌ (cloud reputation) | ✅ | ✅ |
| Open source | ✅ MIT | ✅ Apache-2.0 | ✅ MIT | ✅ MIT |

## Examples

```sh
# 1) Basic usage with Claude Code
agentwall run -- claude

# 2) Aider in strict mode
agentwall run --mode strict -- aider --model gpt-4o

# 3) Interactive request review
agentwall run --explain -- opencode

# 4) CI gate mode
agentwall run --mode strict --fail-on-blocked --json -- claude --headless < task.txt

# 5) Proxy-only mode
agentwall watch

# 6) Audit logs
agentwall log stats
agentwall log grep "sk-ant"

# 7) Session budget
agentwall run --budget 5$ -- claude

# 8) Save and replay session
agentwall run --save-session ./session.jsonl -- aider --model gpt-4o
agentwall run --replay ./session.jsonl -- aider --model gpt-4o
```

## FAQ

**Does this block my agent by default?**
No. `balanced` mode blocks known telemetry while keeping normal agent workflow.

**Does AgentWall upload anything?**
No. Everything stays local and works offline-first.

**What about cert pinning?**
Pinned clients may bypass body-level inspection; AgentWall still applies host-level policy and logs CONNECT behavior.

**Can I use this in CI as a gate?**
Yes, use `--fail-on-blocked`.

## Roadmap

- [x] v0.1: proxy, rule engine, request sanitizers, JSONL audit, CLI
- [x] v0.2: budget controller, replay mode, response guard
- [ ] v0.3: split TUI inspect mode + sparkline
- [ ] v0.4: transparent mode without `HTTPS_PROXY`
- [ ] v1.0: signed releases, SBOM, stable plugin API

## Contributing

The easiest contribution is opening an issue with a telemetry endpoint we missed. We have a one-click template for it.

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and workflow.

## Sponsors

Support via GitHub Sponsors: <https://github.com/sponsors/balyakin>

## Author

Evgeny Balyakin — <https://github.com/balyakin>

## License

MIT. See [LICENSE](LICENSE).
