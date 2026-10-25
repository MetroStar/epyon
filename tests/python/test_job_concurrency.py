"""Tests for the scan concurrency gate and unique job ids."""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "web"))

from api import jobs  # noqa: E402


def _setup(monkeypatch, cap: int):
    monkeypatch.setenv("EPYON_MAX_CONCURRENT_SCANS", str(cap))
    monkeypatch.setattr(jobs, "_slots", None)
    jobs.jobs.clear()
    state = {"running": 0, "peak": 0, "targets": {}}

    async def fake_inner(job_id, target, scan_type, *a, **k):
        key = (target, scan_type)
        state["targets"][key] = state["targets"].get(key, 0) + 1
        assert state["targets"][key] == 1, "same target+type overlapped"
        state["running"] += 1
        state["peak"] = max(state["peak"], state["running"])
        jobs.jobs[job_id]["status"] = "running"
        await asyncio.sleep(0.05)
        jobs.jobs[job_id]["status"] = "completed"
        state["running"] -= 1
        state["targets"][key] -= 1

    monkeypatch.setattr(jobs, "_run_scan_job_inner", fake_inner)
    return state


def _submit(specs):
    async def go():
        tasks = []
        for target, scan_type in specs:
            jid = jobs.new_job_id()
            jobs.create_job(jid, target, scan_type)
            tasks.append(asyncio.create_task(jobs.run_scan_job(jid, target, scan_type)))
        await asyncio.gather(*tasks)
    asyncio.run(go())


def test_cap_limits_parallel_scans(monkeypatch):
    state = _setup(monkeypatch, 2)
    _submit([(f"/t{i}", "quick") for i in range(5)])
    assert state["peak"] == 2
    assert all(j["status"] == "completed" for j in jobs.jobs.values())


def test_same_target_and_type_serialised_but_types_may_overlap(monkeypatch):
    state = _setup(monkeypatch, 4)
    _submit([("/a", "quick"), ("/a", "quick"), ("/a", "full")])
    assert state["peak"] == 2  # the duplicate waited; the other type ran alongside


def test_cancelled_while_queued_never_runs(monkeypatch):
    state = _setup(monkeypatch, 1)

    async def go():
        ids = []
        for t in ("/a", "/b"):
            jid = jobs.new_job_id()
            jobs.create_job(jid, t, "quick")
            ids.append(jid)
        tasks = [asyncio.create_task(jobs.run_scan_job(i, t, "quick")) for i, t in zip(ids, ("/a", "/b"))]
        await asyncio.sleep(0.01)
        jobs.cancel_job(ids[1])
        await asyncio.gather(*tasks)
        return ids

    ids = asyncio.run(go())
    assert jobs.jobs[ids[1]]["status"] == "cancelled"
    assert state["peak"] == 1


def test_new_job_id_unique_within_a_second():
    jobs.jobs.clear()
    ids = []
    for _ in range(5):
        jid = jobs.new_job_id()
        jobs.create_job(jid, "/x", "quick")
        ids.append(jid)
    assert len(set(ids)) == 5
    assert all(len(i) in (14, 16) and i.isdigit() for i in ids)
