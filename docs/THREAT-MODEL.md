# Threat model

This is the project owner's own analysis, written from the code at the time of the audit-anchor
change. It has not been independently reviewed, and the project has not yet been run against real
inference nodes or the real Anthropic API. The invariants it refers to (I1 to I7) are listed in
[`orchestrator/__init__.py`](../orchestrator/__init__.py).

## What is being protected

| Asset | Concern |
|---|---|
| Task content the operator wants kept off third-party services | Sent to the Anthropic API by mistake |
| The Anthropic API key | Disclosure through logs, errors, config or the environment |
| Inference nodes | Use by anything other than the orchestrator |
| The audit trail | Silent alteration after the fact, or task content leaking into it |

## Trust boundaries

```text
 MCP client and its model      trusted to call tools; NOT trusted to choose a lower privacy level
   │ stdio
 orchestrator container        trusted: holds the API key and client key, applies the policy
   ├── internet ──── Anthropic API         outside the operator's control
   └── LAN ───────── Caddy gateway → Ollama    trusted once authenticated
```

The host running the container is trusted. Anyone with root on it, or with write access to the
config, can change the policy, read the secrets and alter the logs.

## Threats and controls

| Threat | Control | Evidence | What remains |
|---|---|---|---|
| Sensitive task sent to the cloud by routing, fallback or override | Level is computed first, cloud removed from the chain, checked again before each cloud call | `tests/test_policy.py` | `high_allows_cloud_fallback` opens `high` by design |
| Sensitive content not recognised | Detectors, keywords, normalisation; `privacy_floor`, `privacy`, `@local` for explicit control | `tests/test_privacy.py` | **Accepted gap.** Detection is heuristic. Personal data, encoded secrets, homoglyphs and plain-language business content can classify as `low`. Use `privacy_floor: "high"` where that matters |
| Caller lowers the level | The `privacy` argument can only raise it | `test_declared_privacy_can_only_raise` | A caller can still omit `@local` or `privacy` |
| Content reaches the calling model's provider | `input_file` and `output_file` | `test_file_io_stays_in_workdir_and_is_not_echoed` | **Out of the server's control.** Inline `task` text is already in the caller's context, and a client with file access can read `workdir` |
| Path traversal through file parameters | Paths resolved and confined to `workdir` | Same test | Anything placed in `workdir` is readable by the server |
| API key disclosure | Secret files with a mode check, no keys in config, environment scrubbed, redacted `repr` | `tests/test_config.py` | `ORCH_ALLOW_ENV_SECRETS=1` weakens this; the key is in process memory while running |
| Rogue client on the LAN uses a node | Client certificate required by the gateway, firewall limits the source address | Fake-node test only | The shipped Caddy and firewall configuration are not run by any test |
| Eavesdropping or redirection towards a node | HTTPS required, pinned private CA, proxies ignored, redirects off | `tests/test_config.py`, `tests/test_policy.py` | `ORCH_ALLOW_INSECURE_LOCAL=1` permits HTTP. "Local" is a configured label; the address is not checked |
| Node downloads or changes models | Gateway forwards inference and version routes only; Ollama has no route out | Configuration only | Model pulls need a manual network change. Model files themselves are trusted |
| Audit record edited, inserted or removed | Hash chain, plus a size and hash anchor beside the log | `tests/test_audit.py` | **Accepted gap.** Both are unkeyed and on the same volume, so someone who can rewrite log and anchor together goes undetected. Copy the anchor elsewhere to raise that bar |
| Task content inferred from the audit trail | No prompt or response text stored | `test_chain_intact_and_no_leaks` | Unsalted hash prefixes allow guess confirmation; matched keywords are stored |
| Runaway use or resource exhaustion | Size, rate, concurrency and cloud-budget limits; finite chains; container limits | `tests/test_inputs.py` | Limits are per process, and each session has its own |
| Compromised dependency or image | Hash-locked Python dependencies; base and gateway images pinned by digest | CI installs with `--require-hashes` | **Accepted gap.** The container's network is a plain bridge, so compromised code could send data anywhere. Pinned images need manual updates. The Ollama image version is the operator's choice |

## Out of scope

Compromise of the host or an inference node, malicious models, prompt injection against the calling
model, and availability against someone on the LAN.

## Suggested next steps

Restrict the container's outbound traffic to the nodes and the Anthropic API, test the shipped
gateway and firewall in CI, and run against real nodes.
