#!/usr/bin/env python3
"""Sync JIRA findings from GitHub Actions using the web backend's jira_client.

This script allows GitHub Actions workflows to trigger JIRA reconciliation
using the same logic as the web backend, without requiring the FastAPI server
to be running.

Usage:
    python3 sync-jira-findings.py --app-name myapp --scan-dir scans/myapp_2026-06-25

Environment variables (required):
    JIRA_BASE_URL, JIRA_USER_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY
"""
import argparse
import asyncio
import json
import sys
from pathlib import Path

# Add web/api to path so we can import jira_client
SCRIPT_DIR = Path(__file__).parent
EPYON_ROOT = (SCRIPT_DIR / ".." / "..").resolve()
WEB_API_DIR = EPYON_ROOT / "web" / "api"
sys.path.insert(0, str(WEB_API_DIR))

try:
    import jira_client
except ImportError as e:
    print(f"ERROR: Could not import jira_client: {e}", file=sys.stderr)
    print("Make sure web/api/jira_client.py exists", file=sys.stderr)
    sys.exit(1)


def find_scan_dirs(epyon_root: Path, app_name: str, limit: int = 2) -> list[Path]:
    """Find the most recent scan directories for an app."""
    scans_dir = epyon_root / "scans"
    if not scans_dir.exists():
        return []
    
    # Find all dirs matching app_name_YYYY-MM-DD_HH-MM-SS pattern
    matching = []
    for d in scans_dir.iterdir():
        if not d.is_dir():
            continue
        # Parse dir name: app_YYYY-MM-DD_HH-MM-SS
        parts = d.name.split("_")
        if len(parts) >= 3:
            candidate_app = "_".join(parts[:-2])  # Everything before date/time
            if candidate_app == app_name:
                matching.append(d)
    
    # Sort by name (which sorts by timestamp) descending
    matching.sort(reverse=True)
    return matching[:limit]


def parse_scan_findings(scan_dir: Path) -> dict:
    """Parse security-findings-summary.json from a scan directory."""
    findings_file = scan_dir / "security-findings-summary.json"
    if not findings_file.exists():
        return {"critical_findings": [], "high_findings": [], "medium_findings": [], "low_findings": []}
    
    try:
        data = json.loads(findings_file.read_text(encoding="utf-8"))
        return data
    except Exception as e:
        print(f"WARNING: Could not parse {findings_file}: {e}", file=sys.stderr)
        return {"critical_findings": [], "high_findings": [], "medium_findings": [], "low_findings": []}


async def main():
    parser = argparse.ArgumentParser(description="Sync JIRA findings from GitHub Actions")
    parser.add_argument("--app-name", required=True, help="Application name")
    parser.add_argument("--scan-dir", help="Current scan directory (optional, will auto-detect)")
    parser.add_argument("--epyon-root", default=str(EPYON_ROOT), help="Epyon root directory")
    args = parser.parse_args()
    
    app_name = args.app_name
    epyon_root = Path(args.epyon_root)
    
    # Read JIRA config from environment
    cfg = jira_client.read_config()
    if not cfg.get("api_token"):
        print("⚠️  JIRA credentials not configured - skipping sync", file=sys.stderr)
        print("   Set JIRA_BASE_URL, JIRA_USER_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY", file=sys.stderr)
        sys.exit(0)
    
    if not cfg.get("create_on_new") and not cfg.get("auto_close"):
        print("ℹ️  JIRA auto-reconciliation disabled (create_on_new and auto_close both false)", file=sys.stderr)
        sys.exit(0)
    
    print(f"🔍 Finding scan directories for {app_name}...")
    scan_dirs = find_scan_dirs(epyon_root, app_name, limit=2)
    
    if len(scan_dirs) < 2:
        print(f"⚠️  Need at least 2 scans to compare. Found: {len(scan_dirs)}", file=sys.stderr)
        if len(scan_dirs) == 1:
            print(f"   Current scan: {scan_dirs[0].name}", file=sys.stderr)
            print("   Skipping JIRA sync (no previous scan to compare against)", file=sys.stderr)
        sys.exit(0)
    
    current_dir = scan_dirs[0]
    previous_dir = scan_dirs[1]
    
    print(f"📊 Current scan:  {current_dir.name}")
    print(f"📊 Previous scan: {previous_dir.name}")
    
    # Parse findings from both scans
    print("🔎 Parsing findings...")
    current_raw = parse_scan_findings(current_dir)
    previous_raw = parse_scan_findings(previous_dir)
    
    current_findings = jira_client.flatten_findings(current_raw)
    previous_findings = jira_client.flatten_findings(previous_raw)
    
    print(f"   Current:  {len(current_findings)} findings")
    print(f"   Previous: {len(previous_findings)} findings")
    
    # Run reconciliation
    print(f"🎫 Reconciling JIRA tickets...")
    try:
        result = await jira_client.reconcile_and_save(
            app_name,
            current_findings,
            previous_findings,
            cfg,
        )
        
        # Print results
        if result["opened"]:
            print(f"✅ Created {len(result['opened'])} ticket(s):")
            for key in result["opened"]:
                url = f"{cfg['base_url']}/browse/{key}"
                print(f"   - {key}: {url}")
        
        if result["closed"]:
            print(f"✅ Closed {len(result['closed'])} ticket(s):")
            for key in result["closed"]:
                print(f"   - {key}")
        
        if result["errors"]:
            print(f"⚠️  {len(result['errors'])} error(s):", file=sys.stderr)
            for err in result["errors"]:
                print(f"   - {err}", file=sys.stderr)
        
        if not result["opened"] and not result["closed"] and not result["errors"]:
            print("ℹ️  No changes - all tickets up to date")
        
        sys.exit(0)
    
    except Exception as e:
        print(f"❌ JIRA reconciliation failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
