-- ============================================================================
-- VaultDB Schema Initialization & Immutability Enforcement
-- Creates the dual-schema structure: app_data (business) & vault_audit (logs)
-- ============================================================================

-- 1. BUSINESS SCHEMA: Holds tables used by the application
CREATE SCHEMA IF NOT EXISTS app_data;

-- Customers table with standard and sensitive columns (ssn, credit_card)
CREATE TABLE IF NOT EXISTS app_data.customers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    ssn VARCHAR(20),                -- Sensitive field for audit detection
    credit_card VARCHAR(30),        -- Sensitive field for audit detection
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Orders table linked to customers
CREATE TABLE IF NOT EXISTS app_data.orders (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES app_data.customers(id) ON DELETE CASCADE,
    amount DECIMAL(10, 2) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'completed',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);


-- 2. AUDIT SCHEMA: Holds immutable audit log records
CREATE SCHEMA IF NOT EXISTS vault_audit;

-- Audit log table: records every query, who ran it, when, and what was touched
CREATE TABLE IF NOT EXISTS vault_audit.audit_logs (
    log_id BIGSERIAL PRIMARY KEY,
    logged_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    app_user VARCHAR(100) NOT NULL,            -- Human user: e.g. sarah@company.com
    user_role VARCHAR(20) NOT NULL,            -- admin, writer, reader
    action VARCHAR(10) NOT NULL,               -- SELECT, INSERT, UPDATE, DELETE
    target_table VARCHAR(100) NOT NULL,        -- e.g. customers, orders
    database_name VARCHAR(50) DEFAULT 'postgres', -- Database where query was executed
    query_text TEXT NOT NULL,                  -- Exact SQL string executed
    rows_affected INTEGER DEFAULT 0,           -- Number of rows returned or changed
    is_sensitive BOOLEAN DEFAULT FALSE,        -- TRUE if query accessed ssn/credit_card
    execution_status VARCHAR(20) NOT NULL,     -- SUCCESS, DENIED, or ERROR
    error_message TEXT                         -- Error description if query failed
);


-- ============================================================================
-- 3. IMMUTABILITY GUARDS (ENGINE-LEVEL DATABASE TRIGGERS)
-- ============================================================================

-- Function that strictly enforces write-once, append-only rules
CREATE OR REPLACE FUNCTION vault_audit.enforce_audit_immutability()
RETURNS TRIGGER AS $$
BEGIN
    -- 1. Block any attempt to UPDATE existing records
    IF (TG_OP = 'UPDATE') THEN
        RAISE EXCEPTION 'VaultDB Security Violation: Audit logs in vault_audit.audit_logs are immutable and cannot be updated.';
    END IF;

    -- 2. Block any attempt to DELETE individual records
    IF (TG_OP = 'DELETE') THEN
        RAISE EXCEPTION 'VaultDB Security Violation: Audit logs in vault_audit.audit_logs are immutable and cannot be deleted.';
    END IF;

    -- 3. Block any attempt to TRUNCATE (mass-wipe) the entire audit table
    IF (TG_OP = 'TRUNCATE') THEN
        RAISE EXCEPTION 'VaultDB Security Violation: TRUNCATE operation is forbidden on vault_audit.audit_logs.';
    END IF;

    -- 4. On INSERT: Force logged_at to server's true current clock time
    -- Prevents attackers from backdating or forging historical timestamps
    IF (TG_OP = 'INSERT') THEN
        NEW.logged_at := CURRENT_TIMESTAMP;
        RETURN NEW;
    END IF;

    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Trigger 1: Intercept UPDATE and DELETE on every row
DROP TRIGGER IF EXISTS trg_audit_no_update_delete ON vault_audit.audit_logs;
CREATE TRIGGER trg_audit_no_update_delete
BEFORE UPDATE OR DELETE ON vault_audit.audit_logs
FOR EACH ROW EXECUTE FUNCTION vault_audit.enforce_audit_immutability();

-- Trigger 2: Intercept TRUNCATE on the audit table
DROP TRIGGER IF EXISTS trg_audit_no_truncate ON vault_audit.audit_logs;
CREATE TRIGGER trg_audit_no_truncate
BEFORE TRUNCATE ON vault_audit.audit_logs
FOR EACH STATEMENT EXECUTE FUNCTION vault_audit.enforce_audit_immutability();

-- Trigger 3: Intercept INSERT to prevent timestamp forgery
DROP TRIGGER IF EXISTS trg_audit_force_timestamp ON vault_audit.audit_logs;
CREATE TRIGGER trg_audit_force_timestamp
BEFORE INSERT ON vault_audit.audit_logs
FOR EACH ROW EXECUTE FUNCTION vault_audit.enforce_audit_immutability();


-- ============================================================================
-- 4. SEED DATA: Sample records for testing
-- ============================================================================
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
