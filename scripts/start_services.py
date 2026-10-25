"""
VaultDB Service Launcher (Legacy Wrapper)
Delegates directly to the unified canonical server entrypoint in server.py.
Maintained for backwards compatibility with historical scripts and CI pipelines.
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from server import main

if __name__ == "__main__":
    main()
