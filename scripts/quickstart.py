"""
VaultDB 1-Command Universal Quickstart
Automated cross-platform launcher for macOS, Linux, and Windows.
Auto-detects environment, initializes database schemas, configures cryptographic
ledger (immudb or native Merkle tree), and launches the workstation server.
"""

import os
import sys
import shutil
import socket
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))


def check_python_version():
    """Ensures Python version is at least 3.10."""
    major, minor = sys.version_info[:2]
    if (major, minor) < (3, 10):
        print(f"[-] Python {major}.{minor} detected. VaultDB requires Python 3.10 or newer.")
        sys.exit(1)
    print(f"[+] Python {major}.{minor}.{sys.version_info.micro} detected ({sys.platform}).")


def ensure_env_file():
    """Creates .env from .env.example if not present."""
    env_path = BASE_DIR / ".env"
    example_path = BASE_DIR / ".env.example"
    if not env_path.exists():
        if example_path.exists():
            shutil.copy(example_path, env_path)
            print("[+] Created default .env from .env.example.")
        else:
            print("[-] Warning: .env file missing.")


def check_postgres_connection() -> bool:
    """Tests connectivity to PostgreSQL."""
    try:
        from config.settings import settings
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            return s.connect_ex((settings.POSTGRES_HOST, settings.POSTGRES_PORT)) == 0
    except Exception:
        return False


def run_database_init():
    """Initializes schemas and seed data if PostgreSQL is reachable."""
    if check_postgres_connection():
        print("[*] PostgreSQL detected. Running automated database initialization...")
        try:
            from scripts.init_databases import main as init_db
            init_db()
        except Exception as e:
            print(f"[-] Database initialization notice: {e}")
    else:
        print("[!] Notice: PostgreSQL server not detected on localhost:5432.")
        print("    VaultDB will operate with in-memory / native ledger fallback.")
        print("    To enable relational mirror: Start PostgreSQL and run 'python scripts/init_databases.py'.")


def main():
    print("=" * 72)
    print("   _   _             _ _   ____  ____  ")
    print("  | | | | __ _ _   _| | |_|  _ \\| __ ) ")
    print("  | | | |/ _` | | | | | __| | | |  _ \\ ")
    print("  \\ \\_/ / (_| | |_| | | |_| |_| | |_) |")
    print("   \\___/ \\__,_|\\__,_|_|\\__|____/|____/ ")
    print("  Universal Immutable Database Middleware & Compliance Platform")
    print("=" * 72)

    check_python_version()
    ensure_env_file()
    run_database_init()

    from scripts.start_services import main as start_main
    start_main()


if __name__ == "__main__":
    main()
