"""Tests for the scan concurrency gate and unique job ids."""
from __future__ import annotations

import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "web"))

from api import jobs  # noqa: E402
from api.parsers import parse_dir_name  # noqa: E402


def _setup(monkeypatch, tmp_path, cap: int):
    monkeypatch.setenv("EPYON_MAX_CONCURRENT_SCANS", str(cap))
    monkeypatch.setattr(jobs, "_gate", None)
    monkeypatch.setattr(jobs, "SCAN_CONFIG_FILE", tmp_path / "scan-config.json")
    jobs.jobs.clear()
    jobs._reserved_job_ids.clear()
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


def test_cap_limits_parallel_scans(monkeypatch, tmp_path):
    state = _setup(monkeypatch, tmp_path, 2)
    _submit([(f"/t{i}", "quick") for i in range(5)])
    assert state["peak"] == 2
    assert all(j["status"] == "completed" for j in jobs.jobs.values())


def test_same_target_and_type_serialised_but_types_may_overlap(monkeypatch, tmp_path):
    state = _setup(monkeypatch, tmp_path, 4)
    _submit([("/a", "quick"), ("/a", "quick"), ("/a", "full")])
    assert state["peak"] == 2  # the duplicate waited; the other type ran alongside


def test_cancelled_while_queued_never_runs(monkeypatch, tmp_path):
    state = _setup(monkeypatch, tmp_path, 1)

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
    jobs._reserved_job_ids.clear()
    ids = []
    for _ in range(5):
        jid = jobs.new_job_id()
        jobs.create_job(jid, "/x", "quick")
        ids.append(jid)
    assert len(set(ids)) == 5
    assert all(len(i) in (14, 16) and i.isdigit() for i in ids)


def test_scan_environment_files_are_unique_per_job():
    env_paths = [
        jobs._write_scan_env_file(["TARGET_DIR=/target-a"]),
        jobs._write_scan_env_file(["TARGET_DIR=/target-b"]),
    ]
    try:
        assert env_paths[0] != env_paths[1]
        assert env_paths[0].read_text() == "TARGET_DIR=/target-a\n"
        assert env_paths[1].read_text() == "TARGET_DIR=/target-b\n"
        assert all(path.stat().st_mode & 0o777 == 0o600 for path in env_paths)
    finally:
        for path in env_paths:
            path.unlink(missing_ok=True)


def test_scan_dir_reservation_uses_distinct_reader_compatible_names(monkeypatch, tmp_path):
    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 10, 26, 1, 2, 3, tzinfo=timezone.utc)

    monkeypatch.setattr(jobs, "datetime", FixedDateTime)

    first_name, first_dir = jobs._reserve_scan_dir(tmp_path, "my-app")
    second_name, second_dir = jobs._reserve_scan_dir(tmp_path, "my-app")

    assert first_dir != second_dir
    assert first_name == "my-app_2026-10-26_01-02-03"
    assert second_name == "my-app_2026-10-26_01-02-04"
    assert parse_dir_name(first_name)["target"] == "my-app"
    assert parse_dir_name(second_name)["target"] == "my-app"


def test_new_job_id_reserves_ids_before_jobs_are_created():
    jobs.jobs.clear()
    jobs._reserved_job_ids.clear()

    first = jobs.new_job_id()
    second = jobs.new_job_id()

    assert first != second
    assert {first, second} == jobs._reserved_job_ids

    jobs.release_job_id(first)
    assert first not in jobs._reserved_job_ids


def test_saved_setting_overrides_env_and_clamps(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path, 2)
    assert jobs.concurrency_source() == "env"
    assert jobs.save_max_concurrent(3) == 3
    assert jobs._max_concurrent() == 3 and jobs.concurrency_source() == "saved"
    assert jobs.save_max_concurrent(999) == jobs.MAX_CONCURRENT_CEILING


def test_raising_limit_releases_queued_scans(monkeypatch, tmp_path):
    state = _setup(monkeypatch, tmp_path, 1)

    async def go():
        ids = []
        for t in ("/a", "/b", "/c"):
            jid = jobs.new_job_id()
            jobs.create_job(jid, t, "quick")
            ids.append((jid, t))
        tasks = [asyncio.create_task(jobs.run_scan_job(i, t, "quick")) for i, t in ids]
        await asyncio.sleep(0.01)
        jobs.save_max_concurrent(3)
        await jobs.wake_queue()
        await asyncio.gather(*tasks)

    asyncio.run(go())
    assert state["peak"] == 3
