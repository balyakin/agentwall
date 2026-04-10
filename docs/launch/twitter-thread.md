# Twitter thread draft

1/ I built AgentWall: a zero-config network firewall for AI coding agents.

2/ Run your CLI agent with one command:
`agentwall run -- claude`

3/ It shows every outbound request in real time and blocks known telemetry endpoints.

4/ It redacts secrets before they leave your machine (API keys, tokens, private keys).

5/ It also scans incoming responses and can sanitize/block leaked secrets.

6/ Built-in budget controller stops runaway spend:
`agentwall run --budget 5$ -- claude`

7/ CI mode turns policy violations into failing builds:
`--mode strict --fail-on-blocked --json`

8/ Single static Go binary. No Node. No Docker. No cloud dependency.
