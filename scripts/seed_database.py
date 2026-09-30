"""
Database Seeding Script for VaultDB
Populates PostgreSQL and immudb with enterprise-scale banking, transaction,
and compliance policy datasets.
"""

import sys
import random
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

import psycopg
from config.settings import settings
from src.vault_db.core.engine import VaultEngine


def seed_database():
    print("=" * 70)
    print(" VaultDB Enterprise Dataset Seeder")
    print("=" * 70)

    # 1. Update Schema & Tables in PostgreSQL
    print("[*] Updating schema and tables in PostgreSQL...")
    schema_sql = """
    CREATE SCHEMA IF NOT EXISTS app_data;
    CREATE SCHEMA IF NOT EXISTS vault_audit;

    -- Users & Roles
    CREATE TABLE IF NOT EXISTS app_data.users (
        email VARCHAR(80) PRIMARY KEY,
        full_name VARCHAR(100) NOT NULL,
        role VARCHAR(20) NOT NULL,
        department VARCHAR(50) DEFAULT 'Retail',
        status VARCHAR(20) DEFAULT 'active',
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    -- Accounts
    CREATE TABLE IF NOT EXISTS app_data.accounts (
        id SERIAL PRIMARY KEY,
        account_number VARCHAR(30) UNIQUE,
        name VARCHAR(100) NOT NULL,
        account_type VARCHAR(30) DEFAULT 'Checking',
        ssn VARCHAR(20) DEFAULT '***-**-1234',
        balance DECIMAL(15, 2) NOT NULL,
        status VARCHAR(20) DEFAULT 'active',
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    -- Transactions
    CREATE TABLE IF NOT EXISTS app_data.transactions (
        id SERIAL PRIMARY KEY,
        account_id INT REFERENCES app_data.accounts(id),
        transaction_type VARCHAR(30) DEFAULT 'TRANSFER',
        amount DECIMAL(15, 2) NOT NULL,
        merchant VARCHAR(100),
        status VARCHAR(20) DEFAULT 'completed',
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    -- Compliance Policies
    CREATE TABLE IF NOT EXISTS app_data.compliance_policies (
        policy_code VARCHAR(30) PRIMARY KEY,
        title VARCHAR(100) NOT NULL,
        standard VARCHAR(50) NOT NULL,
        description TEXT,
        enforcement_level VARCHAR(20) DEFAULT 'STRICT'
    );

    -- Audit Logs (PostgreSQL Redundancy)
    CREATE TABLE IF NOT EXISTS vault_audit.audit_logs (
        log_id SERIAL PRIMARY KEY,
        logged_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        app_user VARCHAR(80),
        user_role VARCHAR(20),
        action VARCHAR(20),
        target_table VARCHAR(50),
        query_text TEXT,
        execution_status VARCHAR(20)
    );

    -- Schema Upgrades for Existing Tables
    ALTER TABLE app_data.users DROP CONSTRAINT IF EXISTS users_role_check;
    ALTER TABLE app_data.users ADD CONSTRAINT users_role_check CHECK (role IN ('customer', 'employee', 'admin', 'auditor'));
    ALTER TABLE app_data.users ADD COLUMN IF NOT EXISTS full_name VARCHAR(100) DEFAULT 'User';
    ALTER TABLE app_data.users ADD COLUMN IF NOT EXISTS department VARCHAR(50) DEFAULT 'Retail';
    ALTER TABLE app_data.users ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active';
    ALTER TABLE app_data.users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;

    ALTER TABLE app_data.accounts ADD COLUMN IF NOT EXISTS account_number VARCHAR(30);
    ALTER TABLE app_data.accounts ADD COLUMN IF NOT EXISTS account_type VARCHAR(30) DEFAULT 'Checking';
    ALTER TABLE app_data.accounts ADD COLUMN IF NOT EXISTS ssn VARCHAR(20) DEFAULT '***-**-1234';
    ALTER TABLE app_data.accounts ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'active';
    ALTER TABLE app_data.accounts ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;

    ALTER TABLE app_data.transactions ADD COLUMN IF NOT EXISTS transaction_type VARCHAR(30) DEFAULT 'TRANSFER';
    ALTER TABLE app_data.transactions ADD COLUMN IF NOT EXISTS merchant VARCHAR(100);
    ALTER TABLE app_data.transactions ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;

    -- Indexes for high-throughput scalability
    CREATE INDEX IF NOT EXISTS idx_accounts_status ON app_data.accounts(status);
    CREATE INDEX IF NOT EXISTS idx_transactions_account_id ON app_data.transactions(account_id);
    CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON app_data.transactions(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_transactions_status ON app_data.transactions(status);
    CREATE INDEX IF NOT EXISTS idx_audit_logged_at ON vault_audit.audit_logs(logged_at DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_app_user ON vault_audit.audit_logs(app_user);

    -- Permissions
    GRANT USAGE ON SCHEMA app_data, vault_audit TO vault_user;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app_data TO vault_user;
    GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA app_data, vault_audit TO vault_user;
    GRANT SELECT, INSERT ON vault_audit.audit_logs TO vault_user;
    """

    with psycopg.connect(settings.postgres_admin_conninfo, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute(schema_sql)
    print("[+] Database schemas, constraints, and indexes updated successfully.")

    # 2. Seed Users
    print("\n[*] Seeding enterprise users & role profiles...")
    users = [
        ("admin@bank.com", "Chief Security Officer (Admin)", "admin", "SecOps"),
        ("compliance.lead@bank.com", "Helen Vance (Compliance Officer)", "auditor", "Regulatory Compliance"),
        ("sarah.auditor@bank.com", "Sarah Lin (Internal Auditor)", "auditor", "Internal Audit"),
        ("john@bank.com", "Johnathan Reed (Senior Loan Officer)", "employee", "Commercial Lending"),
        ("marcus.teller@bank.com", "Marcus Vance (Branch Teller)", "employee", "Retail Banking"),
        ("priya.patel@bank.com", "Priya Patel (Treasury Analyst)", "employee", "Treasury Operations"),
        ("david.invest@bank.com", "David Kim (Wealth Manager)", "employee", "Private Wealth"),
        ("rachel.ops@bank.com", "Rachel Green (Fraud Analyst)", "employee", "Risk & Fraud"),
        ("alice@bank.com", "Alice Smith (Private Client)", "customer", "Private Banking"),
        ("bob.ross@gmail.com", "Robert Ross (Retail Client)", "customer", "Retail Banking"),
        ("carlos.m@techcorp.io", "Carlos Mendez (TechCorp CFO)", "customer", "Corporate"),
        ("diana.prince@wayne.com", "Diana Prince (Global Treasurer)", "customer", "Enterprise"),
        ("elena.rostova@nexus.org", "Elena Rostova (Nexus Foundation)", "customer", "Institutional"),
        ("frank.miller@apex.co", "Franklin Miller (Apex Capital)", "customer", "Capital Markets"),
        ("grace.hopper@mit.edu", "Grace Hopper (Academic Endowment)", "customer", "Endowments"),
    ]

    with psycopg.connect(settings.postgres_admin_conninfo, autocommit=True) as conn:
        with conn.cursor() as cur:
            for email, name, role, dept in users:
                cur.execute("""
                    INSERT INTO app_data.users (email, full_name, role, department)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (email) DO UPDATE SET full_name = EXCLUDED.full_name, role = EXCLUDED.role, department = EXCLUDED.department;
                """, (email, name, role, dept))
    print(f"[+] {len(users)} enterprise users seeded.")

    # 3. Seed Accounts
    print("\n[*] Seeding institutional and retail accounts...")
    accounts_seed = [
        (1, "ACC-1001", "Alice Smith", "Private Checking", "452-98-1123", 99999.00),
        (2, "ACC-1002", "Robert Ross", "High-Yield Savings", "219-54-8842", 24500.50),
        (3, "ACC-1003", "TechCorp Global Escrow", "Corporate Escrow", "981-12-3341", 1450000.00),
        (4, "ACC-1004", "Nexus Foundation Reserve", "Institutional Treasury", "764-88-2910", 3890250.75),
        (5, "ACC-1005", "Apex Capital Liquidity", "Treasury Liquidity", "312-76-9041", 8200400.00),
        (6, "ACC-1006", "Franklin & Partners LLC", "Commercial Operating", "554-19-4821", 412900.25),
        (7, "ACC-1007", "Grace Hopper Endowment", "Endowment Custody", "662-34-1198", 12500000.00),
        (8, "ACC-1008", "David Kim Client Trust", "Fiduciary Trust", "882-99-3401", 670150.00),
        (9, "ACC-1009", "Priya Patel Brokerage", "Investment Brokerage", "102-45-7721", 89400.00),
        (10, "ACC-1010", "Starlight Media Ventures", "Corporate Operating", "409-88-5120", 543000.00),
        (11, "ACC-1011", "Nordic Clean Energy Fund", "ESG Investment", "901-33-2194", 9500000.00),
        (12, "ACC-1012", "Horizon Health Systems", "Healthcare Payroll", "220-41-8973", 1820450.50),
        (13, "ACC-1013", "Quantum Logistics Ltd", "Supply Chain Escrow", "731-90-4412", 740900.00),
        (14, "ACC-1014", "Sophia Williams", "Premier Checking", "119-28-5634", 45800.00),
        (15, "ACC-1015", "Lucas Montgomery", "Private Wealth Advisory", "847-19-3382", 2150000.00),
    ]

    # Generate additional accounts up to 35
    first_names = ["James", "Emma", "Liam", "Olivia", "Noah", "Ava", "William", "Isabella", "Benjamin", "Mia"]
    last_names = ["Anderson", "Thomas", "Jackson", "White", "Harris", "Martin", "Thompson", "Garcia", "Martinez", "Robinson"]
    types = ["Checking", "Savings", "Money Market", "Certificate of Deposit"]

    for idx in range(16, 36):
        acc_num = f"ACC-{1000 + idx}"
        name = f"{random.choice(first_names)} {random.choice(last_names)}"
        acc_type = random.choice(types)
        ssn = f"{random.randint(100, 999)}-{random.randint(10, 99)}-{random.randint(1000, 9999)}"
        balance = round(random.uniform(5000.0, 500000.0), 2)
        accounts_seed.append((idx, acc_num, name, acc_type, ssn, balance))

    with psycopg.connect(settings.postgres_admin_conninfo, autocommit=True) as conn:
        with conn.cursor() as cur:
            for acc in accounts_seed:
                cur.execute("""
                    INSERT INTO app_data.accounts (id, account_number, name, account_type, ssn, balance)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO UPDATE SET
                        account_number = EXCLUDED.account_number,
                        name = EXCLUDED.name,
                        account_type = EXCLUDED.account_type,
                        ssn = EXCLUDED.ssn,
                        balance = EXCLUDED.balance;
                """, acc)
            # Reset sequence to max id
            cur.execute("SELECT setval(pg_get_serial_sequence('app_data.accounts', 'id'), COALESCE(max(id), 1)) FROM app_data.accounts;")
    print(f"[+] {len(accounts_seed)} institutional accounts seeded.")

    # 4. Seed Compliance Policies
    print("\n[*] Seeding regulatory compliance standards...")
    policies = [
        ("GDPR-ART-30", "Records of Processing Activities", "GDPR Art. 30", "Maintains an immutable record of processing activities including categories of data and data subject accesses.", "STRICT"),
        ("HIPAA-164-312", "Audit Controls & Technical Safeguards", "HIPAA §164.312(b)", "Hardware, software, and procedural mechanisms that record and examine activity in information systems containing electronic protected health information.", "MANDATORY"),
        ("PCI-DSS-REQ-10", "Log and Monitor All Access to System Components", "PCI-DSS Req 10", "Audit trails linked to individual users, automated audit trail for all system components, and tamper-proof log protection.", "STRICT"),
        ("SOC2-CC6-1", "Logical and Physical Access Controls", "SOC 2 Type II", "Logical access security software and infrastructure to protect information assets from unauthorized alteration.", "AUDITED"),
        ("SOX-404", "Management Assessment of Internal Controls", "Sarbanes-Oxley 404", "Internal controls over financial reporting including data integrity safeguards and traceability of ledger changes.", "STRICT"),
    ]

    with psycopg.connect(settings.postgres_admin_conninfo, autocommit=True) as conn:
        with conn.cursor() as cur:
            for p in policies:
                cur.execute("""
                    INSERT INTO app_data.compliance_policies (policy_code, title, standard, description, enforcement_level)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (policy_code) DO UPDATE SET title = EXCLUDED.title, standard = EXCLUDED.standard, description = EXCLUDED.description;
                """, p)
    print(f"[+] {len(policies)} regulatory compliance standards seeded.")

    # 5. Seed Realistic Transactions (75+ entries)
    print("\n[*] Generating high-volume financial transaction history...")
    merchants = [
        "SWIFT Global Settlement", "Federal Reserve Wire", "Stripe Clearinghouse",
        "JPMorgan Treasury Services", "Bloomberg Liquidity Hub", "Amazon AWS EMEA",
        "Apex Clearinghouse", "Deloitte Advisory Settlement", "Euroclear Settlement",
        "Goldman Sachs Prime Brokerage", "Healthcare Providers Network", "Target Distribution"
    ]
    tx_types = ["WIRE", "TRANSFER", "DEPOSIT", "PURCHASE", "SETTLEMENT", "PAYROLL"]
    statuses = ["completed", "completed", "completed", "pending", "flagged"]

    tx_records = []
    base_time = datetime.now(timezone.utc) - timedelta(days=30)

    for i in range(1, 85):
        acc_id = random.randint(1, len(accounts_seed))
        t_type = random.choice(tx_types)
        amt = round(random.uniform(150.00, 250000.00), 2)
        merchant = random.choice(merchants)
        status = random.choice(statuses)
        created = base_time + timedelta(hours=i * 8, minutes=random.randint(0, 59))
        tx_records.append((i, acc_id, t_type, amt, merchant, status, created))

    with psycopg.connect(settings.postgres_admin_conninfo, autocommit=True) as conn:
        with conn.cursor() as cur:
            for tx in tx_records:
                cur.execute("""
                    INSERT INTO app_data.transactions (id, account_id, transaction_type, amount, merchant, status, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO NOTHING;
                """, tx)
            cur.execute("SELECT setval(pg_get_serial_sequence('app_data.transactions', 'id'), COALESCE(max(id), 1)) FROM app_data.transactions;")
    print(f"[+] {len(tx_records)} financial transactions seeded.")

    # 6. Seed Realistic Audit Trail into immudb & PostgreSQL
    print("\n[*] Committing enterprise audit events into immudb cryptographic ledger...")
    engine = VaultEngine()

    sample_audit_events = [
        ("alice@bank.com", "SELECT * FROM app_data.accounts WHERE id = 1;"),
        ("john@bank.com", "SELECT name, balance FROM app_data.accounts WHERE id = 3;"),
        ("john@bank.com", "UPDATE app_data.transactions SET status = 'completed' WHERE id = 5;"),
        ("compliance.lead@bank.com", "SELECT * FROM app_data.compliance_policies;"),
        ("sarah.auditor@bank.com", "SELECT * FROM app_data.transactions WHERE amount > 100000;"),
        ("admin@bank.com", "SELECT email, full_name, role FROM app_data.users;"),
        # Prohibited violation events
        ("john@bank.com", "UPDATE app_data.accounts SET balance = 99999 WHERE id = 1;"),
        ("alice@bank.com", "DELETE FROM app_data.transactions WHERE id = 2;"),
        ("carlos.m@techcorp.io", "SELECT * FROM app_data.users;"),
        # Sensitive SSN queries
        ("admin@bank.com", "SELECT name, ssn, balance FROM app_data.accounts WHERE id = 1;"),
        ("alice@bank.com", "SELECT name, ssn FROM app_data.accounts WHERE id = 1;"),
    ]

    for user, query in sample_audit_events:
        try:
            engine.execute(query=query, app_user=user)
        except Exception:
            pass  # Expected violations are recorded as DENIED in immudb

    final_state = engine.get_ledger_state()
    engine.close()

    print(f"[+] immudb cryptographic ledger state updated:")
    print(f"    - Database:           {final_state['database']}")
    print(f"    - Current Tx Height:  #{final_state['tx_id']}")
    print(f"    - Merkle Root Hash:   {final_state['root_hash']}")
    print("=" * 70)
    print("[SUCCESS] Enterprise dataset seeding complete and ready for production/demo!")
    print("=" * 70)


if __name__ == "__main__":
    seed_database()
