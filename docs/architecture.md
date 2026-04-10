# Architecture

AgentWall runs as a local forward proxy (`127.0.0.1:8723` by default) and supervises a child AI-agent process.

Core flow:

1. `agentwall run -- <agent>` starts proxy + child.
2. Child receives `HTTP_PROXY/HTTPS_PROXY` + CA env vars.
3. Every request passes through rule engine:
   - block
   - sanitize
   - allow
4. Request body/header sanitizers redact secrets before egress.
5. Response guard detects/sanitizes/blocks incoming leaks.
6. Budget controller tracks usage and blocks on limit exceed.
7. Every event is rendered in terminal and written to JSONL audit log.

See `AGENTWALL_SPEC.md` for detailed product and UX requirements.
