# Adding a Rule

## User-level rule (local)

Edit `~/.agentwall/config.yaml`:

```yaml
rules:
  - id: block_internal
    action: block
    host: "internal.example.com"
```

## Project-level rule (repo)

Create `.agentwall.yaml` in your repository root:

```yaml
rules:
  - id: allow_metrics
    action: allow
    host: "metrics.my-team.dev"
```

## Test rule behavior

```sh
agentwall rules test https://internal.example.com/v1
```

Rule precedence:

`block > sanitize > allow > default policy`
