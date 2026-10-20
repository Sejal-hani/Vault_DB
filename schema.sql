-- ==============================================================================
-- VaultDB v2.0 Enterprise Schema Definition
-- Dual-Storage Architecture: PostgreSQL (Relational) + immudb (Merkle Ledger)
-- ==============================================================================

CREATE SCHEMA IF NOT EXISTS app_data;
CREATE SCHEMA IF NOT EXISTS vault_audit;

-- ------------------------------------------------------------------------------
-- 1. User Identity & Role Directory
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app_data.users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(80) UNIQUE NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    role VARCHAR(20) NOT NULL,
    department VARCHAR(50) DEFAULT 'Retail',
    status VARCHAR(20) DEFAULT 'active',
    password_hash VARCHAR(255),
    api_key VARCHAR(64),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_users_api_key ON app_data.users(api_key);

-- ------------------------------------------------------------------------------
-- 2. Bank Accounts (Contains Sensitive PII: SSN, High-Value Balances)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app_data.accounts (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES app_data.users(id),
    account_number VARCHAR(30) UNIQUE,
    name VARCHAR(100) NOT NULL,
    account_type VARCHAR(30) DEFAULT 'Checking',
    ssn VARCHAR(255) DEFAULT '***-**-1234',
    balance DECIMAL(15, 2) NOT NULL,
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_accounts_user_id ON app_data.accounts(user_id);
CREATE INDEX IF NOT EXISTS idx_accounts_balance ON app_data.accounts(balance DESC);

-- ------------------------------------------------------------------------------
-- 3. Financial Transactions (50,000+ to 1,000,000+ Records)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app_data.transactions (
    id SERIAL PRIMARY KEY,
    account_id INT REFERENCES app_data.accounts(id),
    transaction_type VARCHAR(30) DEFAULT 'TRANSFER',
    amount DECIMAL(15, 2) NOT NULL,
    merchant VARCHAR(100),
    status VARCHAR(20) DEFAULT 'completed',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_transactions_account_id ON app_data.transactions(account_id);
CREATE INDEX IF NOT EXISTS idx_transactions_amount ON app_data.transactions(amount DESC);
CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON app_data.transactions(created_at DESC);

-- ------------------------------------------------------------------------------
-- 4. Access Requests & Temporary Approval Workflows (V2 Scope)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app_data.access_requests (
    id SERIAL PRIMARY KEY,
    user_email VARCHAR(80) NOT NULL REFERENCES app_data.users(email) ON DELETE CASCADE,
    requested_role VARCHAR(20) NOT NULL,
    requested_table VARCHAR(50) DEFAULT '*',
    duration_hours INT DEFAULT 24,
    reason TEXT NOT NULL,
    status VARCHAR(20) DEFAULT 'PENDING',
    requested_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    reviewed_by VARCHAR(80),
    reviewed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_access_requests_user ON app_data.access_requests(user_email);
CREATE INDEX IF NOT EXISTS idx_access_requests_status ON app_data.access_requests(status);

-- ------------------------------------------------------------------------------
-- 5. Relational Audit Trail Mirror (Synchronized with immudb)
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vault_audit.audit_logs (
    log_id SERIAL PRIMARY KEY,
    logged_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    app_user VARCHAR(80),
    user_role VARCHAR(20),
    action VARCHAR(20),
    target_table VARCHAR(50),
    query_text TEXT,
    execution_status VARCHAR(20),
    immudb_tx_id INT,
    immudb_tx_hash VARCHAR(128)
);
ALTER TABLE vault_audit.audit_logs ADD COLUMN IF NOT EXISTS immudb_tx_id INT;
ALTER TABLE vault_audit.audit_logs ADD COLUMN IF NOT EXISTS immudb_tx_hash VARCHAR(128);
CREATE INDEX IF NOT EXISTS idx_audit_logged_at ON vault_audit.audit_logs(logged_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_app_user ON vault_audit.audit_logs(app_user);
CREATE INDEX IF NOT EXISTS idx_audit_immudb_tx ON vault_audit.audit_logs(immudb_tx_id);

-- ------------------------------------------------------------------------------
-- 6. Role Permissions & Immutability Rules
-- ------------------------------------------------------------------------------
DO $role$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vault_user') THEN
        CREATE ROLE vault_user WITH LOGIN PASSWORD 'vault123';
    END IF;
END
$role$;

GRANT USAGE ON SCHEMA app_data, vault_audit TO vault_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app_data TO vault_user;
GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA app_data, vault_audit TO vault_user;

-- Revoke mutation rights on audit logs to enforce append-only immutability
REVOKE ALL ON vault_audit.audit_logs FROM PUBLIC;
REVOKE ALL ON vault_audit.audit_logs FROM vault_user;
GRANT SELECT, INSERT ON vault_audit.audit_logs TO vault_user;

-- ------------------------------------------------------------------------------
-- 7. Database-Level Immutability Triggers (Zero-Trust Enforcement)
-- ------------------------------------------------------------------------------
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
