#!/usr/bin/env python3
"""
Epyon Web UI entry point.

Convenience wrapper for starting the FastAPI web interface.
"""

import sys


def main():
    """Start Epyon web UI."""
    try:
        import uvicorn
    except ImportError:
        print("❌  Error: Web UI dependencies not installed", file=sys.stderr)
        print("   Install with: pip install epyon-scanner[web]", file=sys.stderr)
        return 1
    
    from epyon import EPYON_ROOT
    
    web_dir = EPYON_ROOT / "web"
    
    if not web_dir.exists():
        print(f"❌  Error: Web UI directory not found at {web_dir}", file=sys.stderr)
        return 1
    
    print(f"""
🚀  Starting Epyon Web UI...

    URL: http://127.0.0.1:8000
    
    Press Ctrl+C to stop
""")
    
    try:
        uvicorn.run(
            "api.main:app",
            host="127.0.0.1",
            port=8000,
            app_dir=str(web_dir),
            log_level="info",
        )
        return 0
    except KeyboardInterrupt:
        print("\n⚠️  Web UI stopped", file=sys.stderr)
        return 0


if __name__ == "__main__":
    sys.exit(main())
