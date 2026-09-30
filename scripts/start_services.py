"""
VaultDB Service Launcher
Starts immudb background service (if not already running) and serves the FastAPI application.
"""

import sys
import time
import socket
import subprocess
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

import uvicorn
from config.settings import settings


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.8)
        return s.connect_ex((host, port)) == 0


def ensure_immudb_running() -> subprocess.Popen | None:
    if is_port_in_use(settings.IMMUDB_PORT, settings.IMMUDB_HOST):
        print(f"[+] immudb service is already active on port {settings.IMMUDB_PORT}.")
        return None

    binary_path = BASE_DIR / "bin" / "immudb.exe"
    if not binary_path.exists():
        print(f"[-] Warning: {binary_path} not found! Please ensure immudb server is running.")
        return None

    data_dir = BASE_DIR / "data" / "immudb"
    data_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(binary_path),
        "--dir", str(data_dir),
        "--pgsql-server=false",
        "--web-server=false",
        "--port", str(settings.IMMUDB_PORT),
    ]

    print(f"[*] Launching immudb server on port {settings.IMMUDB_PORT}...")
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
    )

    # Wait for port to become available
    for _ in range(20):
        if is_port_in_use(settings.IMMUDB_PORT, settings.IMMUDB_HOST):
            print(f"[+] immudb server started successfully (PID: {proc.pid}).")
            return proc
        time.sleep(0.3)

    print("[-] Warning: immudb did not start within expected timeout.")
    return proc


def main():
    print("=" * 70)
    print(" VaultDB Enterprise: Scalable Immutable Database Middleware")
    print(f" Version: {settings.VERSION}")
    print("=" * 70)

    immudb_proc = ensure_immudb_running()

    print(f"[*] Starting FastAPI Web Server at http://localhost:{settings.APP_PORT} ...")
    print(f"[*] Interactive API Docs (Swagger): http://localhost:{settings.APP_PORT}/docs")
    print(f"[*] Dashboard UI: http://localhost:{settings.APP_PORT}/")
    print("=" * 70)

    try:
        uvicorn.run(
            "src.vault_db.api.app:app",
            host=settings.APP_HOST,
            port=settings.APP_PORT,
            reload=False,
            log_level="info",
        )
    except KeyboardInterrupt:
        print("\nShutting down VaultDB services...")
    finally:
        if immudb_proc:
            print("[*] Terminating immudb background process...")
            immudb_proc.terminate()
            immudb_proc.wait(timeout=5)


if __name__ == "__main__":
    main()
