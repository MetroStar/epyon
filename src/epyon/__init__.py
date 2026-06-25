"""
Epyon Security Scanner

A comprehensive DevSecOps security scanner with 16 security tool layers,
DISA STIG compliance assessment, and automated GitHub Actions workflows.
"""

__version__ = "3.11.8"
__author__ = "MetroStar Systems"
__license__ = "MIT"

from pathlib import Path
import os

# Package root directory
PACKAGE_ROOT = Path(__file__).parent

# Epyon installation root (where epyon.sh lives)
# When installed from git, this will be the repository root
# When installed from PyPI (future), files will be in site-packages
_possible_roots = [
    PACKAGE_ROOT.parent.parent,  # Development: src/epyon -> project root
    Path(os.environ.get("EPYON_ROOT", "")),  # Environment variable override
]

EPYON_ROOT = None
for root in _possible_roots:
    if root and (root / "epyon.sh").exists():
        EPYON_ROOT = root
        break

if EPYON_ROOT is None:
    # Fallback to current directory (for pip install from git)
    import sys
    EPYON_ROOT = Path(sys.prefix) / "epyon"
    if not EPYON_ROOT.exists():
        EPYON_ROOT = Path.cwd()

__all__ = [
    "__version__",
    "PACKAGE_ROOT",
    "EPYON_ROOT",
]
