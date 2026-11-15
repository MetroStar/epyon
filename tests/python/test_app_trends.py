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


def test_only_nightly_and_full_scans_count_and_one_point_per_day():
    scans = [_scan(1, "nightly", high=10), _scan(2, "quick", high=0), _scan(3, "full", high=9),
             _scan(3, "full", high=10), _scan(4, "stig")]
    t = app_trend(scans)  # quick and stig are ignored; nightly and full are pooled
    assert t["scans_compared"] == 2 and t["status"] == "Stable"
    assert app_trend([_scan(1, "nightly")])["status"] == "Not enough data"
    assert app_trend([_scan(1, "quick"), _scan(2, "quick")])["status"] == "Not enough data"
