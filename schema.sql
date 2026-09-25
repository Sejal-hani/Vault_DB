-- VaultDB Schema

CREATE SCHEMA IF NOT EXISTS app_data;
CREATE SCHEMA IF NOT EXISTS vault_audit;

-- 1. Simple Business Tables
CREATE TABLE IF NOT EXISTS app_data.users (
    email VARCHAR(50) PRIMARY KEY,
    role VARCHAR(20) NOT NULL
);

CREATE TABLE IF NOT EXISTS app_data.accounts (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    balance DECIMAL(10, 2) NOT NULL
);

CREATE TABLE IF NOT EXISTS app_data.transactions (
    id SERIAL PRIMARY KEY,
    account_id INT,
    amount DECIMAL(10, 2) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending'
);
CREATE INDEX IF NOT EXISTS idx_transactions_account_id ON app_data.transactions(account_id);

-- 2. Audit Trail
CREATE TABLE IF NOT EXISTS vault_audit.audit_logs (
    log_id SERIAL PRIMARY KEY,
    logged_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    app_user VARCHAR(50),
    user_role VARCHAR(20),
    action VARCHAR(20),
    target_table VARCHAR(50),
    query_text TEXT,
    execution_status VARCHAR(20)
);

-- 3. Indexes for Fast Audit Lookups
CREATE INDEX IF NOT EXISTS idx_audit_logged_at ON vault_audit.audit_logs(logged_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_app_user ON vault_audit.audit_logs(app_user);

-- 4. Sample Data
INSERT INTO app_data.users (email, role) VALUES
    ('admin@bank.com', 'admin'),
    ('john@bank.com', 'employee'),
    ('alice@bank.com', 'customer')
ON CONFLICT (email) DO UPDATE SET role = EXCLUDED.role;

INSERT INTO app_data.accounts (id, name, balance) VALUES
    (1, 'Alice Smith', 5000.00),
    (2, 'Bob Johnson', 1200.00)
ON CONFLICT (id) DO NOTHING;

INSERT INTO app_data.transactions (id, account_id, amount, status) VALUES
    (1, 1, 150.00, 'completed'),
    (2, 2, 50.00, 'pending')
ON CONFLICT (id) DO NOTHING;


-- 5. Immutability via GRANT and REVOKE (PostgreSQL Engine Permissions)
DO $role$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vault_user') THEN
        CREATE ROLE vault_user WITH LOGIN PASSWORD 'vault123';
    END IF;
END
$role$;

-- Grant business operations on app_data
GRANT USAGE ON SCHEMA app_data, vault_audit TO vault_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app_data TO vault_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA app_data, vault_audit TO vault_user;

-- Enforce Audit Immutability: Only SELECT and INSERT allowed; REVOKE UPDATE, DELETE, TRUNCATE
REVOKE ALL ON vault_audit.audit_logs FROM PUBLIC;
REVOKE ALL ON vault_audit.audit_logs FROM vault_user;
GRANT SELECT, INSERT ON vault_audit.audit_logs TO vault_user;

