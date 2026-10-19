"""
Database Initialization and Seeding Script
Initializes PostgreSQL schemas, triggers, demo users with hashed credentials,
seed business data, and verifies the immudb ledger.
"""

import sys
import random
from datetime import datetime, timezone, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

import psycopg
from config.settings import settings
from src.vault_db.auth.security import hash_password
from src.vault_db.storage.immudb_vault import ImmudbVault

DEMO_USERS = [
    {
        "email": "admin@bank.com",
        "full_name": "Chief Security Officer",
        "role": "admin",
        "department": "SecOps",
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
        "department": "Internal Audit",
        "password": "AuditorPass123!",
        "api_key": "vlt_key_auditor2_3e4f5a6b7c8d9e0f",
    },
    {
        "email": "john@bank.com",
        "full_name": "Johnathan Reed",
        "role": "employee",
        "department": "Commercial Lending",
        "password": "EmployeePass123!",
        "api_key": "vlt_key_employee_1a2b3c4d5e6f7a8b",
    },
    {
        "email": "alice@bank.com",
        "full_name": "Alice Smith",
        "role": "customer",
        "department": "Private Banking",
        "password": "CustomerPass123!",
        "api_key": "vlt_key_customer_4d5e6f7a8b9c0d1e",
    },
]

ACCOUNTS = [
    (1, "ACC-1001", "Alice Smith", "Private Checking", "452-98-1123", 99999.00),
    (2, "ACC-1002", "Robert Ross", "High-Yield Savings", "219-54-8842", 24500.50),
    (3, "ACC-1003", "TechCorp Global Escrow", "Corporate Escrow", "981-12-3341", 1450000.00),
    (4, "ACC-1004", "Nexus Foundation Reserve", "Institutional Treasury", "764-88-2910", 3890250.75),
    (5, "ACC-1005", "Apex Capital Liquidity", "Treasury Liquidity", "312-76-9041", 8200400.00),
    (6, "ACC-1006", "Franklin & Partners LLC", "Commercial Operating", "554-19-4821", 412900.25),
    (7, "ACC-1007", "Grace Hopper Endowment", "Endowment Custody", "662-34-1198", 12500000.00),
    (8, "ACC-1008", "David Kim Client Trust", "Fiduciary Trust", "882-99-3401", 670150.00),
]

POLICIES = [
    ("GDPR-ART-30", "Records of Processing Activities", "GDPR Art. 30", "Maintains an immutable record of processing activities.", "STRICT"),
    ("HIPAA-164-312", "Audit Controls & Technical Safeguards", "HIPAA §164.312(b)", "Mechanisms that record and examine activity in information systems.", "MANDATORY"),
    ("PCI-DSS-REQ-10", "Log and Monitor All Access", "PCI-DSS Req 10", "Audit trails linked to individual users and tamper-proof log protection.", "STRICT"),
    ("SOX-404", "Management Assessment of Internal Controls", "Sarbanes-Oxley 404", "Data integrity safeguards and traceability of ledger changes.", "STRICT"),
]


def init_postgres():
    print(f"[*] Initializing PostgreSQL at {settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}...")
    schema_path = BASE_DIR / "schema.sql"

    if not schema_path.exists():
        print(f"[-] Error: {schema_path} not found.")
        return False

    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    try:
        with psycopg.connect(settings.postgres_admin_conninfo, autocommit=True) as conn:
            with conn.cursor() as cur:
                # 1. Apply schema and triggers
                cur.execute(schema_sql)

                # 2. Seed Users with PBKDF2 hashes and API keys
                for u in DEMO_USERS:
                    h = hash_password(u["password"])
                    cur.execute("""
                        INSERT INTO app_data.users (email, full_name, role, department, status, password_hash, api_key)
                        VALUES (%s, %s, %s, %s, 'active', %s, %s)
                        ON CONFLICT (email) DO UPDATE SET
                            full_name = EXCLUDED.full_name,
                            role = EXCLUDED.role,
                            department = EXCLUDED.department,
                            password_hash = EXCLUDED.password_hash,
                            api_key = EXCLUDED.api_key;
                    """, (u["email"], u["full_name"], u["role"], u["department"], h, u["api_key"]))

                # 3. Seed Accounts
                for acc in ACCOUNTS:
                    cur.execute("""
                        INSERT INTO app_data.accounts (id, account_number, name, account_type, ssn, balance)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            account_number = EXCLUDED.account_number,
                            name = EXCLUDED.name,
                            balance = EXCLUDED.balance;
                    """, acc)
                cur.execute("SELECT setval(pg_get_serial_sequence('app_data.accounts', 'id'), COALESCE(max(id), 1)) FROM app_data.accounts;")

                # 4. Seed Compliance Policies
                for p in POLICIES:
                    cur.execute("""
                        INSERT INTO app_data.compliance_policies (policy_code, title, standard, description, enforcement_level)
                        VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT (policy_code) DO UPDATE SET
                            title = EXCLUDED.title,
                            standard = EXCLUDED.standard,
                            description = EXCLUDED.description;
                    """, p)

                # 5. Seed Initial Transactions
                merchants = ["Federal Reserve Wire", "SWIFT Clearinghouse", "JPMorgan Settlement", "Euroclear Settlement"]
                tx_types = ["TRANSFER", "WIRE", "DEPOSIT", "PAYROLL"]
                base_time = datetime.now(timezone.utc) - timedelta(days=7)
                for i in range(1, 25):
                    cur.execute("""
                        INSERT INTO app_data.transactions (id, account_id, transaction_type, amount, merchant, status, created_at)
                        VALUES (%s, %s, %s, %s, %s, 'completed', %s)
                        ON CONFLICT (id) DO NOTHING;
                    """, (i, random.randint(1, len(ACCOUNTS)), random.choice(tx_types), round(random.uniform(500.0, 50000.0), 2), random.choice(merchants), base_time + timedelta(hours=i * 6)))
                cur.execute("SELECT setval(pg_get_serial_sequence('app_data.transactions', 'id'), COALESCE(max(id), 1)) FROM app_data.transactions;")

        print("[+] PostgreSQL schemas, triggers, and seed data initialized successfully.")
        return True
    except Exception as e:
        print(f"[-] PostgreSQL initialization error: {e}")
        return False


def init_immudb():
    print(f"[*] Connecting to immudb at {settings.immudb_address}...")
    try:
        immudb = ImmudbVault()
        state = immudb.get_ledger_state()
        print(f"[+] immudb ledger active (Database: {state['database']}, Current Tx: #{state['tx_id']})")
        immudb.close()
        return True
    except Exception as e:
        print(f"[-] immudb connection failed: {e}")
        return False


def main():
    pg_ok = init_postgres()
    immu_ok = init_immudb()
    if pg_ok and immu_ok:
        print("[+] All database components are functioning and ready.")
    else:
        print("[-] One or more components reported an error.")


if __name__ == "__main__":
    main()
