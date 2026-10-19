"""
Applies Auth Columns, Pre-Seeded Passwords/API Keys, and Database-Level Immutability Triggers.
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

import psycopg
from config.settings import settings
from src.vault_db.auth.security import hash_password


DEMO_USERS = [
    {
        "email": "admin@bank.com",
        "full_name": "Chief Security Officer",
        "role": "admin",
        "department": "Security & Core Architecture",
        "password": "AdminPass123!",
        "api_key": "vlt_key_admin_9a8b7c6d5e4f3a2b",
    },
    {
        "email": "compliance.lead@bank.com",
        "full_name": "Helen Vance",
        "role": "auditor",
        "department": "Regulatory Compliance",
        "password": "AuditorPass123!",
        "api_key": "vlt_key_auditor_5d6e7f8a9b0c1d2e",
    },
    {
        "email": "sarah.auditor@bank.com",
        "full_name": "Sarah Lin",
        "role": "auditor",
        "department": "Independent Audit",
        "password": "AuditorPass123!",
        "api_key": "vlt_key_auditor2_3e4f5a6b7c8d9e0f",
    },
    {
        "email": "john@bank.com",
        "full_name": "Johnathan Reed",
        "role": "employee",
        "department": "Branch Operations",
        "password": "EmployeePass123!",
        "api_key": "vlt_key_employee_1a2b3c4d5e6f7a8b",
    },
    {
        "email": "rachel.ops@bank.com",
        "full_name": "Rachel Green",
        "role": "employee",
        "department": "Risk & Fraud Clearing",
        "password": "EmployeePass123!",
        "api_key": "vlt_key_employee2_7a8b9c0d1e2f3a4b",
    },
    {
        "email": "alice@bank.com",
        "full_name": "Alice Smith",
        "role": "customer",
        "department": "Retail Banking",
        "password": "CustomerPass123!",
        "api_key": "vlt_key_customer_4d5e6f7a8b9c0d1e",
    },
    {
        "email": "carlos.m@techcorp.io",
        "full_name": "Carlos Mendez",
        "role": "customer",
        "department": "Commercial Treasury",
        "password": "CustomerPass123!",
        "api_key": "vlt_key_customer2_9a8b7c6d5e4f3a2b",
    },
]


def apply_migration():
    print("[*] Connecting to PostgreSQL using admin credentials...")
    with psycopg.connect(settings.postgres_admin_conninfo, autocommit=True) as conn:
        with conn.cursor() as cur:
            # 1. Add auth columns to app_data.users
            print("[*] Adding password_hash and api_key to app_data.users...")
            cur.execute("""
                ALTER TABLE app_data.users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);
                ALTER TABLE app_data.users ADD COLUMN IF NOT EXISTS api_key VARCHAR(64);
                CREATE INDEX IF NOT EXISTS idx_users_api_key ON app_data.users(api_key);
                GRANT ALL ON TABLE app_data.users TO vault_user;
                GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA app_data, vault_audit TO vault_user;
            """)

            # 2. Seed / Update users with secure hashes and API keys
            print("[*] Seeding demo users with hashed credentials...")
            for u in DEMO_USERS:
                h = hash_password(u["password"])
                cur.execute("""
                    INSERT INTO app_data.users (email, full_name, role, department, status, password_hash, api_key)
                    VALUES (%s, %s, %s, %s, 'active', %s, %s)
                    ON CONFLICT (email) DO UPDATE SET
                        full_name = EXCLUDED.full_name,
                        role = EXCLUDED.role,
                        password_hash = EXCLUDED.password_hash,
                        api_key = EXCLUDED.api_key;
                """, (u["email"], u["full_name"], u["role"], u["department"], h, u["api_key"]))
                print(f"    - Seeded: {u['email']} [{u['role']}] with key {u['api_key']}")

            # 3. Add Immutability Triggers to vault_audit.audit_logs
            print("[*] Applying PostgreSQL immutability triggers on vault_audit.audit_logs...")
            cur.execute("""
                CREATE OR REPLACE FUNCTION vault_audit.prevent_audit_log_tampering()
                RETURNS TRIGGER AS $$
                BEGIN
                    RAISE EXCEPTION 'VaultDB Immutability Violation: vault_audit.audit_logs is append-only. UPDATE, DELETE, and TRUNCATE are strictly prohibited.';
                END;
                $$ LANGUAGE plpgsql;

                DROP TRIGGER IF EXISTS trg_no_update_delete_audit ON vault_audit.audit_logs;
                CREATE TRIGGER trg_no_update_delete_audit
                BEFORE UPDATE OR DELETE ON vault_audit.audit_logs
                FOR EACH ROW EXECUTE FUNCTION vault_audit.prevent_audit_log_tampering();

                DROP TRIGGER IF EXISTS trg_no_truncate_audit ON vault_audit.audit_logs;
                CREATE TRIGGER trg_no_truncate_audit
                BEFORE TRUNCATE ON vault_audit.audit_logs
                FOR EACH STATEMENT EXECUTE FUNCTION vault_audit.prevent_audit_log_tampering();
            """)
            print("[+] PostgreSQL Immutability Triggers successfully applied.")


if __name__ == "__main__":
    apply_migration()
