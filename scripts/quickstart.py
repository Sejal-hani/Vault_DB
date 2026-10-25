"""
VaultDB 1-Command Universal Quickstart
Automated cross-platform launcher delegating to the unified server entrypoint.
Maintained for backwards compatibility with README and SETUP documentation.
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from server import main

if __name__ == "__main__":
    main()
