"""I4 / I7: the audit trail is hash-chained and never contains prompts or secrets."""

import hashlib
import io
import json
import logging
import subprocess
import sys
from pathlib import Path

import pytest

import orchestrator as orch
from orchestrator.audit import AuditLog
from conftest import FAKE_CLOUD_KEY

ROOT = Path(__file__).resolve().parent.parent
VERIFIER = ROOT / "tools" / "verify-audit.py"
SENSITIVE = ["Hunter2", "AKIAIOSFODNN7EXAMPLE", "projet-atlas acquisition", "fix this bug in my loop"]


def chain_breaks(lines):
    return [i for i, (prev, cur) in enumerate(zip(lines, lines[1:]))
            if json.loads(cur)["prev"] != hashlib.sha256(prev.encode()).hexdigest()]


@pytest.fixture
def populated_audit(make, audit_file):
    """Run a realistic mix of calls, capturing stderr logs too."""
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(orch.JsonFormatter())
    logging.getLogger().addHandler(handler)

    async def scenario():
        o, _ = make({"privacy_keywords": {"critical": ["projet-atlas"]}})
        await o.call("route_task", {"task": "my password is Hunter2!"})
        await o.call("route_task", {"task": "AKIAIOSFODNN7EXAMPLE fails"})
        await o.call("route_task", {"task": "Summarise the projet-atlas acquisition memo"})
        await o.call("execute_task", {"task": "fix this bug in my loop"})
        await o.call("execute_task", {"task": "internal infrastructure notes, pw Hunter2"})
        await o.call("execute_task", {"task": "internal notes Hunter2", "override": "@claude"})
        await o.call("route_task", {"task": ["not a string"]})

    import asyncio
    try:
        asyncio.run(scenario())
    finally:
        logging.getLogger().removeHandler(handler)
    return audit_file.read_text().splitlines(), buf.getvalue()


def test_chain_intact_and_no_leaks(populated_audit):
    lines, stderr = populated_audit
    assert len(lines) >= 8
    assert chain_breaks(lines) == []
    blob = "\n".join(lines) + stderr
    assert [s for s in SENSITIVE + [FAKE_CLOUD_KEY] if s in blob] == []


def test_editing_one_record_breaks_chain_there(populated_audit):
    lines, _ = populated_audit
    # Hide that a task was sent to the cloud.
    tampered = list(lines)
    i = next(n for n, line in enumerate(lines) if '"executed_on": "claude_api"' in line)
    rec = json.loads(tampered[i])
    rec["executed_on"], rec["executed_local"] = "local_m5", True
    tampered[i] = json.dumps(rec, sort_keys=True, ensure_ascii=False)
    assert chain_breaks(tampered) == [i]


def test_decisions_record_locality(populated_audit):
    lines, _ = populated_audit
    executed = [json.loads(line) for line in lines if '"executed_on": "' in line]
    assert {(r["executed_on"], r["executed_local"]) for r in executed} == {("claude_api", False), ("local_m5", True)}


def test_verifier_accepts_real_log_and_flags_forged_tail(populated_audit, tmp_path, audit_file):
    forged = tmp_path / "forged.jsonl"
    forged.write_text(audit_file.read_text() + json.dumps({"event": "decision", "prev": "genesis"}) + "\n")
    assert subprocess.run([sys.executable, VERIFIER, audit_file], capture_output=True).returncode == 0
    assert subprocess.run([sys.executable, VERIFIER, forged], capture_output=True).returncode == 2


def verify(path):
    return subprocess.run([sys.executable, VERIFIER, path], capture_output=True, text=True).returncode


def write_records(path, count=6):
    log = AuditLog(str(path))
    for n in range(count):
        log.emit("decision", n=n)


def test_verifier_detects_records_removed_from_the_end(tmp_path):
    log = tmp_path / "audit.jsonl"
    write_records(log)
    assert verify(log) == 0
    log.write_text("".join(log.read_text().splitlines(keepends=True)[:-2]))
    assert verify(log) == 2


def test_restart_on_a_shortened_log_leaves_a_permanent_record(tmp_path):
    log = tmp_path / "audit.jsonl"
    write_records(log)
    log.write_text("".join(log.read_text().splitlines(keepends=True)[:-2]))
    AuditLog(str(log)).emit("startup")
    assert '"event": "audit_anchor_mismatch"' in log.read_text()
    assert verify(log) == 2


def test_verifier_requires_the_anchor(tmp_path):
    log = tmp_path / "audit.jsonl"
    write_records(log)
    Path(f"{log}.anchor").unlink()
    assert verify(log) == 2


def test_two_open_writers_keep_one_chain(tmp_path):
    log = tmp_path / "audit.jsonl"
    first, second = AuditLog(str(log)), AuditLog(str(log))
    for n in range(4):
        first.emit("decision", n=n)
        second.emit("decision", n=n)
    assert chain_breaks(log.read_text().splitlines()) == []
    assert verify(log) == 0


def test_concurrent_processes_keep_one_chain(tmp_path):
    log = tmp_path / "audit.jsonl"
    code = ("import sys; from orchestrator.audit import AuditLog\n"
            "log = AuditLog(sys.argv[1])\n"
            "[log.emit('decision', n=n) for n in range(50)]\n")
    procs = [subprocess.Popen([sys.executable, "-c", code, str(log)], cwd=ROOT, stderr=subprocess.DEVNULL)
             for _ in range(4)]
    assert [p.wait() for p in procs] == [0] * 4
    lines = log.read_text().splitlines()
    assert len(lines) == 200
    assert verify(log) == 0
