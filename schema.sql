-- VaultDB Schema & Immutability Triggers

-- 1. Business Data Schema
CREATE SCHEMA IF NOT EXISTS app_data;

CREATE TABLE IF NOT EXISTS app_data.customers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    ssn VARCHAR(20),
    credit_card VARCHAR(30),
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS app_data.orders (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES app_data.customers(id) ON DELETE CASCADE,
    amount DECIMAL(10, 2) NOT NULL,
    status VARCHAR(20) DEFAULT 'completed',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);


-- 2. Audit Trail Schema
CREATE SCHEMA IF NOT EXISTS vault_audit;

CREATE TABLE IF NOT EXISTS vault_audit.audit_logs (
    log_id BIGSERIAL PRIMARY KEY,
    logged_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP NOT NULL,
    app_user VARCHAR(100) NOT NULL,
    user_role VARCHAR(20) NOT NULL,
    action VARCHAR(20) NOT NULL,
    target_table VARCHAR(255) NOT NULL,
    database_name VARCHAR(50) DEFAULT 'postgres',
    query_text TEXT NOT NULL,
    rows_affected INTEGER DEFAULT 0,
    is_sensitive BOOLEAN DEFAULT FALSE,
    execution_status VARCHAR(20) NOT NULL,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_logged_at ON vault_audit.audit_logs(logged_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_app_user ON vault_audit.audit_logs(app_user);



-- 3. Immutability Trigger Function & Triggers
CREATE OR REPLACE FUNCTION vault_audit.enforce_audit_immutability()
RETURNS TRIGGER AS $$
BEGIN
    -- Block modifications and deletions
    IF TG_OP IN ('UPDATE', 'DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'Audit logs cannot be updated, deleted, or truncated.';
    END IF;

    -- Enforce server timestamp on new logs
    NEW.logged_at := CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply Row Trigger (Insert/Update/Delete) and Statement Trigger (Truncate)
DROP TRIGGER IF EXISTS trg_audit_immutability ON vault_audit.audit_logs;
CREATE TRIGGER trg_audit_immutability
BEFORE INSERT OR UPDATE OR DELETE ON vault_audit.audit_logs
FOR EACH ROW EXECUTE FUNCTION vault_audit.enforce_audit_immutability();

DROP TRIGGER IF EXISTS trg_audit_no_truncate ON vault_audit.audit_logs;
CREATE TRIGGER trg_audit_no_truncate
BEFORE TRUNCATE ON vault_audit.audit_logs
FOR EACH STATEMENT EXECUTE FUNCTION vault_audit.enforce_audit_immutability();


-- 4. Dummy Data
INSERT INTO app_data.customers (name, email, ssn, credit_card) VALUES
    ('Alice Smith', 'alice@example.com', '123-45-6789', '4111-2222-3333-4444'),
    ('Bob Johnson', 'bob@example.com', '987-65-4321', '5500-0000-0000-0004'),
    ('Charlie Brown', 'charlie@example.com', '555-55-5555', '3782-8224-6310-005')
ON CONFLICT (email) DO NOTHING;

INSERT INTO app_data.orders (customer_id, amount, status) VALUES
    (1, 150.50, 'completed'),
    (1, 49.99, 'completed'),
    (2, 299.00, 'pending')
ON CONFLICT DO NOTHING;
