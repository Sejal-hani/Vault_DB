"""
VaultDB Application Server & Universal Launcher
Canonical enterprise entrypoint for the VaultDB Middleware & Security Workstation.

Handles automated runtime verification, environmental configuration, database
schema verification, cryptographic ledger detection, and FastAPI/Uvicorn hosting.
"""

import os
import sys
import time
import socket
import shutil
import logging
import subprocess
from pathlib import Path

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import uvicorn
from config.settings import settings

logger = logging.getLogger("vaultdb.server")


def check_python_runtime() -> None:
    """Verifies Python runtime meets the minimum required version (3.10+)."""
    major, minor = sys.version_info[:2]
    if (major, minor) < (3, 10):
        print(f"[-] Python {major}.{minor} detected. VaultDB requires Python 3.10 or newer.")
        sys.exit(1)


def ensure_environment_config() -> None:
    """Ensures local .env configuration exists; creates from .env.example if missing."""
    env_file = BASE_DIR / ".env"
    example_file = BASE_DIR / ".env.example"

    if not env_file.exists() and example_file.exists():
        shutil.copy(example_file, env_file)
        print("[+] Created default .env configuration from .env.example.")


def is_port_bound(port: int, host: str = "127.0.0.1") -> bool:
    """Checks whether a TCP port is actively listening."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.8)
        return sock.connect_ex((host, port)) == 0


def verify_database_schemas() -> None:
    """Initializes PostgreSQL schemas and seed data if PostgreSQL is reachable."""
    if is_port_bound(settings.POSTGRES_PORT, settings.POSTGRES_HOST):
        try:
            from scripts.init_databases import main as init_db
            init_db()
        except Exception as e:
            print(f"[!] PostgreSQL initialization notice: {e}")
    else:
        print("[i] PostgreSQL server offline on port 5432. Standalone audit mode active.")


def resolve_cryptographic_ledger() -> subprocess.Popen | None:
    """
    Detects or initializes the cryptographic ledger backend.
    Connects to immudb daemon if active; otherwise activates the native pure-Python Merkle tree.
    """
    if is_port_bound(settings.IMMUDB_PORT, settings.IMMUDB_HOST):
        print(f"[+] immudb daemon active on port {settings.IMMUDB_PORT}.")
        return None

    # On Windows, attempt launching bundled immudb binary if present
    if sys.platform == "win32":
        binary_path = BASE_DIR / "bin" / "immudb.exe"
        if binary_path.exists():
            data_dir = BASE_DIR / "data" / "immudb"
            data_dir.mkdir(parents=True, exist_ok=True)

            cmd = [
                str(binary_path),
                "--dir", str(data_dir),
                "--pgsql-server=false",
                "--web-server=false",
                "--port", str(settings.IMMUDB_PORT),
            ]
            print(f"[*] Launching local immudb server on port {settings.IMMUDB_PORT}...")
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            )
            for _ in range(20):
                if is_port_bound(settings.IMMUDB_PORT, settings.IMMUDB_HOST):
                    print(f"[+] immudb server started successfully (PID: {proc.pid}).")
                    return proc
                time.sleep(0.3)

    # Universal Native Merkle Tree fallback (macOS, Linux, bare-metal Windows)
    print("[i] External immudb daemon not detected on port 3322.")
    print("[+] Activated Native RFC 6962 Merkle Tree Ledger (Pure Python).")
    print("    100% portable on macOS, Linux, and Windows — zero external binaries needed.")
    return None


def print_banner() -> None:
    """Displays startup telemetry and dashboard connection instructions."""
    print("=" * 72)
    print("   _   _             _ _   ____  ____  ")
    print("  | | | | __ _ _   _| | |_|  _ \\| __ ) ")
    print("  | | | |/ _` | | | | | __| | | |  _ \\ ")
    print("  \\ \\_/ / (_| | |_| | | |_| |_| | |_) |")
    print("   \\___/ \\__,_|\\__,_|_|\\__|____/|____/ ")
    print("  Universal Immutable Database Middleware & Compliance Platform")
    print(f"  Version: {settings.VERSION} | Host: {settings.APP_HOST}:{settings.APP_PORT}")
    print("=" * 72)
    print(f"[*] Web Console:  http://localhost:{settings.APP_PORT}/")
    print(f"[*] Health Check: http://localhost:{settings.APP_PORT}/api/health")
    print(f"[*] Audit Ledger: http://localhost:{settings.APP_PORT}/api/logs")
    print("=" * 72)


def main() -> None:
    """Main execution flow for running VaultDB services."""
    check_python_runtime()
    ensure_environment_config()
    print_banner()

    immudb_proc = resolve_cryptographic_ledger()
    verify_database_schemas()

    try:
        uvicorn.run(
            "src.vault_db.api.app:app",
            host=settings.APP_HOST,
            port=settings.APP_PORT,
            reload=False,
            log_level="info",
        )
    except KeyboardInterrupt:
        print("\n[*] Shutting down VaultDB application services...")
    finally:
        if immudb_proc:
            print("[*] Terminating immudb background process...")
            immudb_proc.terminate()
            immudb_proc.wait(timeout=5)


if __name__ == "__main__":
    main()
