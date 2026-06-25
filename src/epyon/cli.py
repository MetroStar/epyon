#!/usr/bin/env python3
"""
Epyon CLI - Command-line interface for the Epyon security scanner.

Provides commands for:
- Installing GitHub Actions workflow into repositories
- Running security scans locally
- Starting the web UI
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from epyon import __version__, EPYON_ROOT


def install_workflow(args):
    """Install Epyon workflow into target repository."""
    target = Path(args.target or Path.cwd()).resolve()
    
    # Check if target is a git repository
    if not (target / ".git").exists():
        print(f"❌  Error: {target} is not a git repository", file=sys.stderr)
        return 1
    
    # Source workflow template
    source = EPYON_ROOT / "bin" / "templates" / "scan-private-repo.yml"
    if not source.exists():
        print(f"❌  Error: Workflow template not found at {source}", file=sys.stderr)
        return 1
    
    # Destination
    dest_dir = target / ".github" / "workflows"
    dest_file = dest_dir / "scan-private-repo.yml"
    
    # Create directory
    dest_dir.mkdir(parents=True, exist_ok=True)
    
    # Copy workflow
    existed = dest_file.exists()
    shutil.copy2(source, dest_file)
    
    tag = "updated" if existed else "installed"
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║  Epyon Security Scanner — workflow {tag:<26}║
╚══════════════════════════════════════════════════════════════╝

  ✅  {dest_file}

  Next steps:
    1. Commit the workflow file:
         git add {dest_file.relative_to(target)}
    
    2. Configure required secrets in GitHub repo settings:
         SONAR_TOKEN, SONAR_HOST_URL  (optional — enables SonarQube)
         JIRA_BASE_URL, JIRA_USER_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY
                                      (optional — enables Jira sync)
         OPENAI_API_KEY               (optional — enables STIG + Garak)
    
    3. Push to GitHub — scans run automatically on push & PRs

  Full documentation: https://github.com/MetroStar/epyon
""")
    return 0


def run_scan(args):
    """Run Epyon security scan."""
    epyon_sh = EPYON_ROOT / "epyon.sh"
    
    if not epyon_sh.exists():
        print(f"❌  Error: epyon.sh not found at {epyon_sh}", file=sys.stderr)
        return 1
    
    # Build command
    cmd = [str(epyon_sh)]
    
    if args.target:
        cmd.extend(["--target", args.target])
    if args.app_name:
        cmd.extend(["--app-name", args.app_name])
    if args.mode:
        cmd.extend(["--mode", args.mode])
    
    # Pass through environment
    env = os.environ.copy()
    
    # Run scan
    try:
        result = subprocess.run(cmd, env=env, cwd=EPYON_ROOT)
        return result.returncode
    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user", file=sys.stderr)
        return 130


def start_web_ui(args):
    """Start Epyon web UI."""
    web_dir = EPYON_ROOT / "web"
    
    if not web_dir.exists():
        print(f"❌  Error: Web UI directory not found at {web_dir}", file=sys.stderr)
        return 1
    
    try:
        # Import here to avoid requiring fastapi for CLI-only usage
        import uvicorn
    except ImportError:
        print("❌  Error: Web UI dependencies not installed", file=sys.stderr)
        print("   Install with: pip install epyon-scanner[web]", file=sys.stderr)
        return 1
    
    host = args.host or "127.0.0.1"
    port = args.port or 8000
    
    print(f"""
🚀  Starting Epyon Web UI...

    URL: http://{host}:{port}
    
    Press Ctrl+C to stop
""")
    
    try:
        uvicorn.run(
            "api.main:app",
            host=host,
            port=port,
            app_dir=str(web_dir),
            reload=args.reload,
            log_level="info",
        )
        return 0
    except KeyboardInterrupt:
        print("\n⚠️  Web UI stopped", file=sys.stderr)
        return 0


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="epyon",
        description="Epyon Security Scanner — 16-layer DevSecOps security scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"epyon {__version__}",
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # install-workflow command
    install_parser = subparsers.add_parser(
        "install-workflow",
        help="Install Epyon GitHub Actions workflow into a repository",
    )
    install_parser.add_argument(
        "--target",
        help="Target repository directory (default: current directory)",
    )
    install_parser.set_defaults(func=install_workflow)
    
    # scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Run Epyon security scan locally",
    )
    scan_parser.add_argument(
        "--target",
        help="Target application directory to scan",
    )
    scan_parser.add_argument(
        "--app-name",
        help="Application name for scan output",
    )
    scan_parser.add_argument(
        "--mode",
        choices=["quick", "nightly", "full", "stig"],
        help="Scan mode (quick/nightly/full/stig)",
    )
    scan_parser.set_defaults(func=run_scan)
    
    # web command
    web_parser = subparsers.add_parser(
        "web",
        help="Start Epyon web UI",
    )
    web_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host to bind to (default: 127.0.0.1)",
    )
    web_parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind to (default: 8000)",
    )
    web_parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload on code changes (dev mode)",
    )
    web_parser.set_defaults(func=start_web_ui)
    
    # Parse arguments
    args = parser.parse_args()
    
    # Show help if no command specified
    if not args.command:
        parser.print_help()
        return 0
    
    # Execute command
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
