# Claude Orchestrator MCP Server

A stdio MCP server for Claude Code that routes each task either to the Anthropic API or to local
Ollama models on the M5 / M970 machines, based on how sensitive the task looks. Sensitive work
never leaves the LAN: if no local machine is reachable, the request fails instead of falling back
to the cloud.

## How routing works

1. **Privacy level** (`low` < `medium` < `high` < `critical`) is the highest of:
   - content detectors (API keys, AWS/GitHub/Slack tokens, JWTs, PEM private keys, credentials in
     URLs, `password=` assignments, valid IBANs, Luhn-valid card numbers) → `critical`
   - keyword lists in English, French, Portuguese and Spanish, matched after Unicode normalisation,
     accent stripping and leetspeak/spacing removal (`p 4 s s w 0 r d` still matches)
   - the configured `privacy_floor`
   - the caller's `privacy` argument (it can only raise the level, never lower it)
   - `high` for anything classified as a security task
2. **Task type** (code, bug fix, analysis, writing, …) picks the preferred provider order for
   `low` / `medium` tasks.
3. **Policy:** `high` and `critical` tasks are local-only (`high` can be opened to Claude with
   `high_allows_cloud_fallback`, `critical` never can). This is enforced again right before every
   cloud call.

Keyword matching is deliberately aggressive and errs on the side of keeping things local. Some
ordinary coding words trip it: `classname` (contains `ssn`), `tokenizer` (`token`), `healthcheck`
(`health`). Those tasks go to a local model, or fail with `NO_ROUTE` if none is up. Use
`route_task` to see why a task was classified the way it was.

If a local node can't be reached, it is skipped for `provider_cooldown_s` (default 30 s) so later
calls don't each wait for the connect timeout. Only connection failures trigger this; HTTP errors
don't. The cooldown is per process, and Claude Code starts one process per session.

## MCP tools

| Tool | Purpose |
|---|---|
| `route_task(task, override?, privacy?)` | Classify and show the routing decision without executing |
| `execute_task(task? \| input_file?, override?, privacy?, output_file?)` | Route and execute |
| `get_routing_history(limit=10)` | Recent decisions (metadata and hashes only, never task text) |
| `check_resources()` | Health of the local inference endpoints |

`override` is one of `@local` / `@private` (local only), `@claude`, `@cheap` (local first)
and `@fast` (lowest estimated latency). `@claude` is refused for `high` / `critical` tasks.

For sensitive material, use `input_file` / `output_file` (paths inside the configured `workdir`).
The content is then read and written by the server and never passes through the calling model's
context.

## Layout

```
orchestrator/                the server package (run with `python -m orchestrator`)
  models.py                  privacy levels, task types, provider ids
  privacy.py                 content detectors, keyword classifier, task classifier
  routing.py                 routing tables and the cloud/local policy
  providers.py               Anthropic and Ollama (mTLS) backends
  core.py                    validation, limits, execution chain, history, error boundary
  config.py / secret.py      non-secret config / secret-file loading
  audit.py / log.py          hash-chained audit trail / stderr-only JSON logging
  server.py                  MCP stdio tools
config.template.json         copy to ./config.json
docker-compose.yml           orchestrator container (no listening port)
Dockerfile                   non-root, read-only, hash-pinned dependencies
requirements.in / .txt       direct deps / pip-compile lockfile with hashes
deploy/
  make-pki.sh                private CA + certs for mTLS between orchestrator and nodes
  inference-node/            per-machine Ollama + Caddy mTLS gateway + firewall
  claude-code.mcp.json       Claude Code MCP config snippet
tools/
  verify-audit.py            verify the audit log hash chain and flag policy alerts
  rotate-anthropic-key.sh    zero-downtime API key rotation
tests/                       pytest suite, grouped by security invariant
.github/workflows/ci.yml     tests against the hash-locked deps + image build and smoke test
```

## Setup

1. **PKI:** `deploy/make-pki.sh <outdir> <m5_ip> <m970_ip>`, then copy certificates as the script
   prints. Keep `ca.key` offline.
2. **Inference nodes:** on each machine, run `deploy/inference-node/` (see the header of its
   `docker-compose.yml`, and `firewall.sh`).
3. **Secrets** (owned by uid 10001, mode 0400):
   - `/etc/claude-orchestrator/secrets/anthropic_api_key`
   - `/etc/claude-orchestrator/pki/{ca.crt,orchestrator.crt,orchestrator.key}`

   API keys are never read from `config.json` (the server refuses to start if it contains
   `api_keys`) and are only read from environment variables when `ORCH_ALLOW_ENV_SECRETS=1`.
4. **Config:** `cp config.template.json config.json` and set the model tags served by each node.
   Unknown limits, non-positive limits and malformed keyword lists are rejected at startup.
5. **Node addresses:** export `M5_IP` and `M970_IP` (the LAN addresses of the nodes). The compose
   file maps them to `m5.lan` / `m970.lan` and refuses to start without them.
6. **Claude Code:** add the contents of `deploy/claude-code.mcp.json` to your MCP config, replacing
   `/path/to/Local-MPC` with your checkout. Claude Code starts the container on demand with
   `docker compose run --rm -T orchestrator-mcp`. Building the image needs BuildKit (`docker buildx`).

Without an Anthropic key the server runs local-only. Without local endpoints, `low` / `medium`
tasks go to Claude and everything else returns `NO_ROUTE`.

## Audit log

Every decision, error and startup is appended to `audit_log_file` as hash-chained JSONL with no
prompt or response text. Check it with:

```bash
python3 tools/verify-audit.py /var/log/claude-orchestrator/audit.jsonl [--since YYYY-MM-DD]
```

Exit code 2 means the chain is broken: a record was edited, removed or inserted. The chain is
unkeyed, so it detects accidental or naive tampering, not an attacker who can rewrite the whole file.

## Tests

```bash
python3.11 -m venv .venv
.venv/bin/pip install --require-hashes --no-deps -r requirements.txt
.venv/bin/pip install "pytest>=8,<9"
.venv/bin/python -m pytest
```

The suite needs `openssl` on the PATH: it generates a throwaway test PKI, runs a fake Ollama server
behind mTLS on an ephemeral port, and drives the real server end to end over MCP stdio. The Anthropic
client is replaced by a recorder, so no real API calls are made and every policy test can assert
exactly what would have left the machine.
