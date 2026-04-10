# Changelog

All notable changes to this project are documented in this file.

## [0.1.0] - 2026-04-10

### Added

- Initial AgentWall MVP implementation.
- Local HTTP/HTTPS proxy with request policy engine.
- Builtin telemetry blocklist and strict allowlist.
- Request sanitization with builtin secret patterns.
- Response guard modes: detect, sanitize, block.
- Budget controller with provider usage extraction.
- Session recorder/replay primitives.
- CLI commands: `run`, `watch`, `replay`, `doctor`, `ca`, `rules`, `log`, `init`, `version`.
- JSONL audit log with tail/grep/stats helpers.
- Unit and integration test baseline, race-safe test run.
