# AgentWall Threat Model

## Protects against

- Accidental API key leakage in outgoing LLM prompts.
- Silent telemetry egress from CLI agents.
- Unauthorized outbound hosts in strict mode.
- Runaway LLM spend loops via local budget limits.
- Secret leakage from incoming model responses.
- Missing network visibility for audit/compliance workflows.

## Does not protect against

- Malicious agent logic that intentionally disables proxy usage.
- Data leakage through local filesystem operations.
- Prompt injection and semantic model jailbreak classes.
- Full TLS body inspection when hard pinning prevents MITM.
- Kernel-level network attack classes (AgentWall is L7 proxy).

## Mitigations and roadmap

- Transparent firewall mode (planned) for non-cooperative clients.
- Expanded compatibility and strict-mode smoke matrix in CI.
- Signed releases + SBOM for supply-chain trust.
