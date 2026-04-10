# FAQ

## Does AgentWall send telemetry?

No. AgentWall is offline-first and does not phone home.

## Will it break my workflow?

`balanced` mode is default and only blocks known telemetry endpoints.

## Can I disable sanitizers?

Yes, but only explicitly with `--no-sanitize` or `AGENTWALL_NO_SANITIZE=1`.

## Can I use it in CI?

Yes, use `--mode strict --fail-on-blocked --json`.

## Where are logs?

`~/.agentwall/log.jsonl` by default.
