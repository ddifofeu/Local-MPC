"""I4 / I6: validation, bounds, history and file I/O."""

import json
import stat
import time

import pytest


async def test_history_contains_no_task_text(make):
    o, _ = make()
    await o.call("route_task", {"task": "my password is Hunter2!"})
    h = await o.call("get_routing_history", {"limit": 10})
    assert h["status"] == "success"
    assert "Hunter2" not in json.dumps(h)


@pytest.mark.parametrize("limit", [0, -1, "5", True])
async def test_bad_history_limit_rejected(make, limit):
    o, _ = make()
    r = await o.call("get_routing_history", {"limit": limit})
    assert r["code"] == "INVALID_INPUT"


@pytest.mark.parametrize("args", [
    {}, {"task": ["a"]}, {"task": "abc\x00def"}, {"task": "   "},
    {"task": "x", "override": "@root"}, {"task": "x", "override": "@openai"}, {"task": "x", "evil": 1},
], ids=["missing", "list", "nul", "empty", "bad_override", "removed_override", "extra_arg"])
async def test_malformed_input_rejected(make, args):
    o, _ = make()
    r = await o.call("route_task", args)
    assert r["code"] == "INVALID_INPUT"


async def test_huge_prompt_rejected_quickly(make):
    o, _ = make()
    t0 = time.monotonic()
    r = await o.call("route_task", {"task": "A" * 50_000_000})
    assert r["code"] == "INVALID_INPUT"
    assert time.monotonic() - t0 < 0.5


async def test_rate_limit(make):
    o, _ = make({"limits": {"rate_per_minute": 5}})
    statuses = [(await o.call("route_task", {"task": "hello"}))["status"] for _ in range(7)]
    assert statuses[:5] == ["success"] * 5
    assert statuses[5] == "error"


async def test_file_io_stays_in_workdir_and_is_not_echoed(make, tmp_path):
    wd = tmp_path / "work"
    wd.mkdir()
    (wd / "in.txt").write_text("mot de passe VPN: Hunter2!")
    o, rec = make(workdir=wd)
    traversal = await o.call("execute_task", {"input_file": "../../etc/passwd"})
    r = await o.call("execute_task", {"input_file": "in.txt", "output_file": "out.txt"})
    assert traversal["code"] == "INVALID_INPUT"
    assert r["status"] == "success"
    assert r["execution"]["provider"] == "local_m5"
    assert "response" not in r["execution"]
    assert stat.S_IMODE((wd / "out.txt").stat().st_mode) == 0o600
    assert rec.sent == []
