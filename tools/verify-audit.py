#!/usr/bin/env python3
"""Verify the hash chain of the orchestrator audit log and print a security summary.

Exit code 0 = chain intact, 2 = chain broken (record edited, deleted or inserted).
Usage: verify-audit.py /var/log/claude-orchestrator/audit.jsonl [--since YYYY-MM-DD]
"""
import argparse
import collections
import hashlib
import json
import sys

ap = argparse.ArgumentParser()
ap.add_argument("path")
ap.add_argument("--since", default="")
a = ap.parse_args()

prev_line = None
breaks, n = [], 0
stats = collections.Counter()
alerts = []
with open(a.path, "rb") as f:
    for i, raw in enumerate(f, 1):
        line = raw.rstrip(b"\n")
        rec = json.loads(line)
        n += 1
        # The server only starts a chain ("genesis") on an empty file, so it is valid on line 1 only.
        expected = "genesis" if prev_line is None else hashlib.sha256(prev_line).hexdigest()
        if rec.get("prev") != expected:
            breaks.append(i)
        prev_line = line
        if rec.get("ts", "") < a.since:
            continue
        ev = rec.get("event")
        stats[ev] += 1
        if ev == "error":
            stats["error:" + rec.get("code", "?")] += 1
            if rec.get("code") == "POLICY_VIOLATION":
                alerts.append(f"line {i}: privacy-downgrade attempt ({rec.get('detail', '')})")
        # Records written before 'executed_local' existed fall back to the provider names.
        local = rec.get("executed_local", rec.get("executed_on") in ("local_m5", "local_m970"))
        if ev == "decision" and rec.get("privacy_level") in ("high", "critical") and \
                rec.get("executed_on") is not None and local is not True:
            alerts.append(f"line {i}: {rec['privacy_level']} task executed on {rec['executed_on']} — INVARIANT I1 BROKEN")
        if ev == "startup":
            stats["key_fp:" + str(rec.get("anthropic_key_fp"))] += 1

print(f"records: {n}")
for k, v in sorted(stats.items()):
    print(f"  {k:40s} {v}")
for al in alerts:
    print("ALERT", al)
if breaks:
    print(f"CHAIN BROKEN at lines {breaks[:20]}", file=sys.stderr)
    sys.exit(2)
print("chain: OK")
