"""
Database Initialization Script
Sets up schemas, seed data, and permissions in PostgreSQL and verifies the immudb ledger.
"""

import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

import psycopg
from config.settings import settings
from src.vault_db.storage.immudb_vault import ImmudbVault


def init_postgres():
    print(f"[*] Initializing PostgreSQL at {settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}...")
    schema_path = BASE_DIR / "schema.sql"

    if not schema_path.exists():
        print(f"[-] Error: {schema_path} not found!")
        return False

    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    try:
        with psycopg.connect(settings.postgres_admin_conninfo, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(schema_sql)
        print("[+] PostgreSQL schemas, tables, and roles successfully initialized.")
        return True
    except Exception as e:
        print(f"[-] PostgreSQL initialization failed: {e}")
        return False


def init_immudb():
    print(f"[*] Connecting to immudb at {settings.immudb_address}...")
    try:
        immudb = ImmudbVault()
        state = immudb.get_ledger_state()
        print(f"[+] immudb ledger ready! Database: {state['database']}, Current Tx: #{state['tx_id']}")
        print(f"    Merkle Root Hash: {state['root_hash']}")
        immudb.close()
        return True
    except Exception as e:
        print(f"[-] immudb connection failed: {e}")
        print("    Ensure immudb server is running: .\\bin\\immudb.exe --dir data/immudb --pgsql-server=false --web-server=false")
        return False


def main():
    print("=" * 65)
    print(" VaultDB: Dual-Storage Initialization (PostgreSQL + immudb)")
    print("=" * 65)

    pg_ok = init_postgres()
    immu_ok = init_immudb()

    print("=" * 65)
    if pg_ok and immu_ok:
        print("[SUCCESS] All database components are fully functioning and ready!")
    else:
        print("[WARNING] One or more components reported an error. Please verify the logs above.")
    print("=" * 65)


if __name__ == "__main__":
    main()
