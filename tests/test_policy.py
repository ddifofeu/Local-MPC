"""I1: HIGH/CRITICAL tasks never reach the cloud, whatever the route, fallback or override."""

import time

HIGH_TASK = "Here is our production database schema and internal hostnames: ..."


async def test_private_override_with_local_down_fails_closed(make):
    o, rec = make(m5_up=False)
    r = await o.call("execute_task", {"task": "Summarise this: DB root pw is Hunter2!", "override": "@private"})
    assert r["status"] == "error"
    assert rec.sent == []


async def test_security_task_with_locals_down_fails_closed(make):
    o, rec = make(m5_up=False)
    r = await o.call("execute_task", {"task": "Audit the security of our VPN config: <paste>"})
    assert r["status"] == "error"
    assert rec.sent == []


async def test_security_task_runs_on_m5_over_mtls(make):
    o, rec = make()
    r = await o.call("execute_task", {"task": "Audit the security of our VPN config: <paste>"})
    assert r["status"] == "success"
    assert r["execution"]["provider"] == "local_m5"
    assert rec.sent == []


async def test_cloud_override_on_high_task_refused(make):
    o, rec = make()
    r = await o.call("execute_task", {"task": HIGH_TASK, "override": "@claude"})
    assert r["code"] == "POLICY_VIOLATION"
    assert rec.sent == []


async def test_high_task_defaults_to_local(make):
    o, rec = make()
    r = await o.call("execute_task", {"task": HIGH_TASK})
    assert r["status"] == "success"
    assert r["execution"]["provider"].startswith("local")
    assert rec.sent == []


async def test_low_task_executes_on_claude(make):
    o, rec = make()
    r = await o.call("execute_task", {"task": "fix this bug in my loop"})
    assert r["execution"]["provider"] == "claude_api"
    assert rec.sent == ["fix this bug in my loop"]


async def test_no_client_cert_rejected_without_cloud_fallback(make):
    o, rec = make(client_cert=False)
    r = await o.call("execute_task", {"task": "internal infrastructure notes"})
    assert r["status"] == "error"
    assert rec.sent == []


async def test_unreachable_nodes_cool_down_and_still_fail_closed(make, audit_file):
    o, rec = make(m5_up=False)
    first = await o.call("execute_task", {"task": "internal infrastructure notes"})
    t0 = time.monotonic()
    second = await o.call("execute_task", {"task": "internal infrastructure notes"})
    assert first["code"] == second["code"] == "UPSTREAM_FAILURE"
    assert rec.sent == []
    assert audit_file.read_text().count('"event": "provider_skipped"') == 2
    assert time.monotonic() - t0 < 0.5


async def test_without_cloud_key_low_task_goes_local(make):
    o, _ = make(cloud=False)
    r = await o.call("execute_task", {"task": "fix this bug in my loop"})
    assert r["execution"]["provider"] == "local_m5"
