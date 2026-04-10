# Contributing

Thanks for contributing to AgentWall.

## Quick dev setup

```sh
go test ./...
go test ./... -race -cover
```

## Rules for contributions

- Keep the project offline-first and privacy-first.
- Do not add telemetry to AgentWall itself.
- Avoid new heavy runtime dependencies.
- Prefer deterministic tests that do not require external network.

## Typical contribution areas

- Add missing telemetry endpoints.
- Improve sanitizer coverage for token formats.
- Add compatibility fixtures for CLI agents.
- Improve docs and troubleshooting.

## Pull request checklist

- [ ] tests pass locally
- [ ] no secrets in fixtures/logs
- [ ] docs updated if behavior changed
- [ ] changelog entry added for user-facing changes
