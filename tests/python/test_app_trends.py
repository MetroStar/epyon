import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "web"))
from api.app_trends import app_trend  # noqa: E402


def _scan(day, scan_type="full", **sev):
    return {"timestamp": f"2026-01-{day:02d}T10:00:00Z", "scan_type": scan_type,
            "critical": 0, "high": 0, "medium": 0, "low": 0, **sev}


def test_improving_declining_stable():
    assert app_trend([_scan(1, high=10), _scan(2, high=4)])["status"] == "Improving"
    assert app_trend([_scan(1, medium=10), _scan(2, medium=30)])["status"] == "Declining"
    assert app_trend([_scan(1, medium=100), _scan(2, medium=98)])["status"] == "Stable"


def test_new_critical_is_declining_even_if_total_risk_drops():
    t = app_trend([_scan(1, medium=2000), _scan(2, critical=1, medium=1900)])
    assert t["status"] == "Declining" and t["critical_high_delta"] == 1


def test_only_same_scan_type_is_compared_and_one_point_per_day():
    scans = [_scan(1, high=10), _scan(2, "quick", high=0), _scan(3, high=9), _scan(3, high=10)]
    t = app_trend(scans)  # latest is a full scan; the quick scan is ignored
    assert t["scans_compared"] == 2 and t["status"] == "Stable"
    assert app_trend([_scan(1)])["status"] == "Not enough data"
