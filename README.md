# privacy-mcp-router

A privacy-aware [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server that lets Claude Code send
each task either to the Anthropic API or to Ollama models on your own machines, under a written
routing policy enforced in code. The project was previously called Local-MPC; it is an **MCP** server
and has nothing to do with multiparty computation.

It is for someone who already runs local inference nodes and wants the choice of "cloud or local"
made by a policy with tests and an audit trail, not remembered task by task.

**What it provides:** with default settings, requests the router treats as `high` or `critical`,
and requests you mark `@local`, are not sent to the Anthropic API by this server. If no local node
can take them, the request fails rather than falling back to the cloud.

**What it does not provide:** a guarantee that sensitive data stays private. Sensitivity detection
is heuristic and misses things, one setting relaxes the policy, and text already in the calling
model's context has reached that model's provider before the router sees it. See
[What is and isn't protected](#what-is-and-isnt-protected).

## Status

An early personal project, at version 0.2.0.

| | |
|---|---|
| **Works today** | Classification, routing, policy enforcement, file-based execution, audit log and its verifier, all exercised through the test suite, including end to end over MCP stdio |
| **Test evidence** | 68 tests passed on 2026-11-06 (Python 3.12.3, Linux). CI runs the tests on Python 3.11, builds the image and smoke-tests MCP `initialize`; see the [Actions tab](https://github.com/ddifofeu/privacy-mcp-router/actions) |
| **Test scope** | The local node is a fake Ollama server behind real mTLS on an ephemeral port. The Anthropic client is replaced by a recorder, so policy tests assert exactly what would have left the machine |
| **Not covered by tests** | The shipped Caddy gateway, `firewall.sh`, the full `docker-compose.yml` restrictions, real Ollama nodes, and real Anthropic API calls |
| **Not yet done** | It has not been run against real inference nodes or the real Anthropic API, and there has been no load test or independent security review. The [threat model](docs/THREAT-MODEL.md) is my own analysis. The design invariants are listed in [`orchestrator/__init__.py`](orchestrator/__init__.py) |

## How a request flows

```text
Claude Code (MCP client)
   │  stdio: task text, or a path inside workdir
   ▼
orchestrator container (no listening port)
   ├─ 1 classify   detectors + keywords + floor + caller's level  →  low … critical
   ├─ 2 route      level + task type + override                   →  ordered provider chain
   ├─ 3 enforce    remove cloud if the level forbids it; re-check before each cloud call
   ├─ 4 execute    try the chain in order, stop at the first success
   └─ 5 record     metadata only  →  hash-chained audit.jsonl
        │                                     │
        │ low / medium                        │ any level
        │ (high only if explicitly opened)    │ HTTPS, private CA, client certificate
        ▼                                     ▼
   Anthropic API                     Caddy gateway on each node
                                     (inference routes and /api/version; all else 403)
                                              │ internal Docker network
                                              ▼
                                            Ollama
```

The shipped configuration names two nodes, and those names are also config keys and audit-log
values. `local_m5` is the primary node, which gets general and security work. `local_m970` is the
secondary node, tried first for data processing and `@cheap`. Replace the addresses and model tags
with your own.

### 1. Classification

Each task gets a privacy level (`low` < `medium` < `high` < `critical`), the highest of:

- **Content detectors** → `critical`: API keys, AWS/GitHub/Slack tokens, JWTs, PEM private keys,
  credentials in URLs, `password=` assignments, valid IBANs, Luhn-valid card numbers.
- **Keyword lists**, matched after Unicode normalisation, accent stripping and leetspeak/spacing
  removal (`p 4 s s w 0 r d` still matches). The lists are mainly English and French, with a few
  Portuguese and Spanish terms. Add your own with `privacy_keywords`.
- **`privacy_floor`**: a deployment-wide minimum.
- **The caller's `privacy` argument**, which can raise the level but never lower it.
- **`high`** for anything classified as a security task.

Task type (code, bug fix, analysis, writing and so on) is classified separately. It chooses the
provider order for `low` and `medium` tasks.

Keyword matching deliberately errs towards local, so ordinary coding words trip it: `classname`
(contains `ssn`), `tokenizer` (`token`), `healthcheck` (`health`). Those tasks go to a local model
or fail. Use `route_task` to see why a task was classified the way it was.

**This is not data-loss prevention.** It finds the patterns and words it knows about. In manual
probes on 2026-11-06 (commit `71832f3`), all of these classified as `low` and were routed to Claude
first:

- a person's name with date of birth, address and phone number
- a Brazilian CPF number
- a base64-encoded `password=` string
- `password` spelled with a Cyrillic letter
- merger terms in plain language
- a Spanish salary note and a Portuguese patient-record request

If you know content is sensitive, say so explicitly rather than relying on detection.

### 2. Routing policy

| Effective level | Provider chain | Reaches the Anthropic API? |
|---|---|---|
| `low`, `medium` | Set by task type. Code, bug fix, analysis, writing: Claude, then primary node. Data processing: secondary, primary, then Claude. Image and real-time tasks: Claude only | Yes |
| `high` | Primary node, then secondary | Only with `high_allows_cloud_fallback: true` (default `false`) |
| `critical` | Primary node, then secondary | Never |

| Override | Effect |
|---|---|
| `@local`, `@private` | Local nodes only, with no cloud fallback, at any level |
| `@claude` | Puts Claude first. Refused for `critical`, and for `high` unless the fallback setting is on |
| `@cheap` | Tries local nodes first, but **a `low` or `medium` task can still fall back to Claude**. This is a cost hint, not a privacy control |
| `@fast` | Reorders the chain by fixed latency estimates |

### 3. Enforcement

The policy is applied twice: when the chain is built, cloud providers are removed if the level
forbids them, whatever the route or override asked for. The check runs again immediately before
each cloud call. Providers that aren't configured are never routable, chains hold at most three
providers, and fallback isn't recursive.

### 4. Failure behaviour

| Situation | Result |
|---|---|
| `high`, `critical` or `@local`, with nodes configured but unreachable | `UPSTREAM_FAILURE`, no cloud call |
| No eligible provider configured | `NO_ROUTE`, no cloud call |
| `@claude` on a level that forbids it | `POLICY_VIOLATION`, no cloud call; `tools/verify-audit.py` reports it as an alert |
| `low` or `medium`, a provider fails | Next provider in the chain, **which may be Claude** |
| `high_allows_cloud_fallback: true`, local nodes fail on a `high` task | Falls back to Claude |
| Per-process cloud budget used up | Cloud skipped and audited; fails if nothing else remains |
| Too many requests, invalid input | `RATE_LIMITED`, `INVALID_INPUT` |

Callers get an error code, a safe message and an `error_id`, never internal details.

If a local node can't be reached, it is skipped for `provider_cooldown_s` (default 30 s) so later
calls don't each wait for the connect timeout. Only connection failures trigger this; HTTP errors
don't. The cooldown, like the cloud budget, is per process, and Claude Code starts one process per
session.

Without an Anthropic key the server runs local-only. Without local endpoints, `low` and `medium`
tasks go to Claude and everything else returns `NO_ROUTE`.

## What is and isn't protected

With the default `high_allows_cloud_fallback: false`, this server does not send a request to the
Anthropic API if it evaluates as `high` or `critical`, or if it carries `@local` or `@private`.
The test suite asserts this with a recorder in place of the cloud client
([`tests/test_policy.py`](tests/test_policy.py)).

That protection has limits:

- **False negatives.** A task that evaluates as `low` or `medium` is eligible for the cloud,
  however sensitive it really is. Use `@local`, `privacy`, custom `privacy_keywords`, or
  `privacy_floor`. Setting `privacy_floor: "high"` makes every request local-only without relying
  on content detection.
- **Configuration exception.** With `high_allows_cloud_fallback: true`, `high` tasks reach Claude
  when local nodes fail, and `@claude` sends them to Claude first. `critical` is unaffected.
- **The calling model.** Text in a `task` argument is already in the calling model's context. If
  that model is hosted (as it is with Claude Code on the Anthropic API), the text has left your
  network before the router runs. Likewise, a response returned inline enters that context.
- **"Local" means "configured as local".** The server requires `https://` for local endpoints but
  doesn't check that an address is on your LAN or that you own the machine.
  `ORCH_ALLOW_INSECURE_LOCAL=1` permits plain HTTP for lab use.

### File-based execution

`execute_task` can read from `input_file` and write to `output_file`, both paths inside the
configured `workdir`. The server does the file I/O, so the payload needn't pass through the calling
model. This holds only under these conditions:

- **Use both parameters.** With `input_file` alone, the response comes back inline and can quote the
  input. With `output_file`, the caller receives the path, hash prefix and length instead.
- **Set the route as well.** A file that classifies as `low` goes to Claude like any other task, so
  add `override: "@local"` or `privacy: "high"` for sensitive files.
- **The caller must not read the files by other means.** The server can't stop a client from opening
  `workdir` with its own tools, and Claude Code has file tools. Keeping this boundary needs client
  permissions that deny access to that directory, or a `workdir` the client's user can't read.
- **`route_task` takes text only.** There is no way to preview a file's classification without
  passing its content through the caller.
- **Some metadata still reaches the caller:** provider, level, task type, length, hash prefix and
  `privacy_reasons`, which name the detector or keyword that matched but not the matched text.

## Security controls

| Area | What is in place | Limit |
|---|---|---|
| **Transport** | Local endpoints must be `https://`. Private CA via `ca_file`, client certificate, proxies ignored, redirects not followed | The orchestrator treats the client certificate as optional. The shipped gateway is what requires it, so a deployment without that gateway may not have mTLS |
| **Inference nodes** | [Caddy gateway](deploy/inference-node/Caddyfile) with TLS 1.3 and required client certificates. Only inference routes and `/api/version` are forwarded. Ollama sits on an internal network with no published port. [`firewall.sh`](deploy/inference-node/firewall.sh) limits the gateway to the orchestrator's address | Not exercised by the tests. The gateway image is pinned by digest, so updates are manual |
| **API key** | Read from secret files, which are refused if group- or world-readable. `api_keys` in config stops startup. Environment variables are ignored and scrubbed unless `ORCH_ALLOW_ENV_SECRETS=1`. Redacted `repr`, no serialisation. [Rotation script](tools/rotate-anthropic-key.sh) | Environment mode is a development convenience. The client TLS key doesn't get the same mode check |
| **Container** | [Compose file](docker-compose.yml): non-root, read-only root filesystem, all capabilities dropped, `no-new-privileges`, PID/memory/CPU limits, no core dumps, no published port. Python dependencies installed with `--require-hashes` | The base image is pinned by digest, so updates are manual. The network is a plain bridge, so **outbound traffic isn't restricted to the nodes and Anthropic** |
| **Inputs** | Type and size checks, rate limit, concurrency limit, per-process cloud budget, paths confined to `workdir` | Limits are per process |
| **Logs and history** | Audit log and `get_routing_history` hold metadata, not prompt or response text ([`tests/test_audit.py`](tests/test_audit.py)) | See below for what metadata can reveal |

## Audit log

Every decision, error and startup is appended to `audit_log_file` as hash-chained JSONL with no
prompt or response text. Check it with:

```bash
python3 tools/verify-audit.py /var/log/claude-orchestrator/audit.jsonl [--since YYYY-MM-DD]
```

Exit code 2 means the chain is broken, the log doesn't match its anchor, or the server recorded such
a mismatch at startup. The tool also prints policy alerts, such as a refused
downgrade, or a `high` or `critical` task recorded as run in the cloud (expected if you enabled
`high_allows_cloud_fallback`).

A hash chain alone can't show that records were cut from the end, so after each append the server
also writes the log's size and last hash to `audit.jsonl.anchor`. Each append takes a file lock and
chains from the file itself, so concurrent Claude Code sessions can share one log.

| Change to the log | Result |
|---|---|
| Record edited, removed from the start or middle, or forged line appended | Chain broken (exit 2) |
| Records removed from the end | Anchor mismatch (exit 2) |
| Anchor deleted | Exit 2 |
| Server restarted on a shortened log | `audit_anchor_mismatch` is written to the log, so the event stays on record |
| Sessions writing at once | Single valid chain |

The chain and anchor are unkeyed and live side by side, so they detect accidental or naive tampering,
not an attacker who can rewrite the whole file and its anchor. Copying the anchor somewhere the
server's host can't alter would raise that bar. Use `--since` after you have reviewed an old mismatch.

Metadata can still reveal something. `privacy_reasons` records the keyword that matched, so a
sensitive custom keyword such as a project name appears in the log and in MCP responses. Task hashes
are unsalted SHA-256 prefixes, so anyone with the log can confirm a guess at a short or predictable
task.

The [threat model](docs/THREAT-MODEL.md) sets these limits out by threat, including the gaps accepted
for now.

## Design decisions and tradeoffs

- **Availability gives way to policy.** A local-only request fails when no node is up. The cost is
  failed tasks, including the false positives above.
- **Over-matching over under-matching.** Aggressive keywords send some harmless coding tasks local.
  It reduces misses, but doesn't remove them.
- **A level can only go up.** The caller can't talk the router down, so a mistaken or
  prompt-injected caller can't lower a level. It also can't correct a false positive.
- **Stdio only.** There is no listening port on the orchestrator, and so no network-facing endpoint
  to authenticate. The cost is one process per session, with per-process limits.
- **One policy function, checked twice.** Routing and execution both ask the same `cloud_allowed`
  question, so a bug in chain construction still meets a check at the call site.

## How this was built

The commits in this repository carry a Claude co-author trailer, so treat the implementation as
AI-assisted. Upstream projects do the heavy lifting: the
[MCP Python SDK](https://github.com/modelcontextprotocol/python-sdk), the Anthropic SDK,
[Ollama](https://ollama.com), [Caddy](https://caddyserver.com) and HTTPX.

## MCP tools

| Tool | Purpose |
|---|---|
| `route_task(task, override?, privacy?)` | Classify and show the routing decision without executing |
| `execute_task(task? \| input_file?, override?, privacy?, output_file?)` | Route and execute |
| `get_routing_history(limit=10)` | Recent decisions (metadata and hashes only, never task text) |
| `check_resources()` | Health of the local inference endpoints |

## Setup

This needs Docker with BuildKit (`docker buildx`) and two inference nodes, since the shipped compose
file requires both addresses. To try the policy without any of that, run the [tests](#tests).

1. **PKI:** `deploy/make-pki.sh <outdir> <m5_ip> <m970_ip>`, passing the primary and secondary node
   addresses, then copy certificates as the script prints. Keep `ca.key` offline.
2. **Inference nodes:** on each machine, run `deploy/inference-node/` (see the header of its
   `docker-compose.yml`, and `firewall.sh`).
3. **Secrets** (owned by uid 10001, mode 0400):
   - `/etc/claude-orchestrator/secrets/anthropic_api_key`
   - `/etc/claude-orchestrator/pki/{ca.crt,orchestrator.crt,orchestrator.key}`

   API keys are never read from `config.json` (the server refuses to start if it contains
   `api_keys`) and are only read from environment variables when `ORCH_ALLOW_ENV_SECRETS=1`.
4. **Config:** `cp config.template.json config.json` and set the model tags served by each node.
   Unknown limits, non-positive limits and malformed keyword lists are rejected at startup.
5. **Node addresses:** export `M5_IP` and `M970_IP` (the nodes' LAN addresses). The compose file
   maps them to `m5.lan` and `m970.lan` and refuses to start without them. For file-based execution,
   set `ORCH_WORKDIR` to the host directory mounted as `/work`.
6. **Claude Code:** add the contents of `deploy/claude-code.mcp.json` to your MCP config, replacing
   `/path/to/privacy-mcp-router` with your checkout. Claude Code starts the container on demand with
   `docker compose run --rm -T orchestrator-mcp`.

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
Dockerfile                   non-root runtime, hash-locked Python dependencies
requirements.in / .txt       direct deps / pip-compile lockfile with hashes
deploy/
  make-pki.sh                private CA + certs for mTLS between orchestrator and nodes
  inference-node/            per-machine Ollama + Caddy mTLS gateway + firewall
  claude-code.mcp.json       Claude Code MCP config snippet
tools/
  verify-audit.py            verify the audit log hash chain and flag policy alerts
  rotate-anthropic-key.sh    API key rotation
  tracker.py                 bug and change tracker (entries in tracker/)
docs/THREAT-MODEL.md         assets, trust boundaries, threats, controls and accepted gaps
tests/                       pytest suite, grouped by security invariant
.github/workflows/ci.yml     tests against the hash-locked deps + image build and smoke test
```

## Tests

```bash
python3.11 -m venv .venv
.venv/bin/pip install --require-hashes --no-deps -r requirements.txt
.venv/bin/pip install "pytest>=8,<9"
.venv/bin/python -m pytest
```

The suite needs `openssl` on the PATH: it generates a throwaway test PKI, runs a fake Ollama server
behind mTLS on an ephemeral port, and drives the real server end to end over MCP stdio. Policy tests
are in [`tests/test_policy.py`](tests/test_policy.py), classification probes in
[`tests/test_privacy.py`](tests/test_privacy.py), and audit tests in
[`tests/test_audit.py`](tests/test_audit.py). `git config core.hooksPath .githooks` runs the tracker
check and the tests before every commit.

## Licence

MIT, see [`LICENSE`](LICENSE).
