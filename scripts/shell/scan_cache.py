"""Bounded, atomic scan caches and cross-process NVD rate limiting."""

import fcntl
import hashlib
import json
import os
import sys
from pathlib import Path
import tempfile
import time
from contextlib import contextmanager


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class JsonCache:
    def __init__(self, directory, ttl, max_entries=2048):
        if ttl <= 0 or max_entries < 1:
            raise ValueError("Cache TTL and capacity must be positive")
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl
        self.max_entries = max_entries

    def get(self, key):
        path = self.directory / (fingerprint(key) + ".json")
        try:
            record = json.loads(path.read_text())
        except FileNotFoundError:
            return None
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            print(f"[WARNING] Ignoring invalid scan cache {path.name}: {error}", file=sys.stderr)
            return None
        if not isinstance(record, dict) or record.get("key") != key:
            return None
        created = record.get("created")
        if not isinstance(created, (int, float)) or not 0 <= time.time() - created < self.ttl:
            return None
        return record.get("data")

    def put(self, key, data):
        with (self.directory / ".write.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            descriptor, temporary = tempfile.mkstemp(prefix=".entry-", dir=self.directory)
            try:
                with os.fdopen(descriptor, "w") as stream:
                    json.dump({"key": key, "created": time.time(), "data": data}, stream)
                os.replace(temporary, self.directory / (fingerprint(key) + ".json"))
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            entries = sorted(self.directory.glob("*.json"), key=lambda entry: entry.stat().st_mtime)
            for entry in entries[:max(0, len(entries) - self.max_entries)]:
                entry.unlink()


@contextmanager
def nvd_request_slot(directory, interval):
    """Serialize shared-cache callers and space every attempt, including retries."""
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / ".nvd-rate.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        lock.seek(0)
        raw = lock.read().strip()
        try:
            previous = float(raw) if raw else 0
        except ValueError as error:
            raise ValueError("Invalid shared NVD rate-limit state") from error
        time.sleep(max(0, min(interval, previous + interval - time.time())))
        try:
            yield
        finally:
            lock.seek(0)
            lock.truncate()
            lock.write(str(time.time()))
            lock.flush()
