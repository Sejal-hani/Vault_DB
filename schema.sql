-- ============================================================================
-- VaultDB Schema Initialization
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
    query_text TEXT NOT NULL,                  -- Exact SQL string executed
    rows_affected INTEGER DEFAULT 0,           -- Number of rows returned or changed
    is_sensitive BOOLEAN DEFAULT FALSE,        -- TRUE if query accessed ssn/credit_card
    execution_status VARCHAR(20) NOT NULL,     -- SUCCESS, DENIED, or ERROR
    error_message TEXT                         -- Error description if query failed
);


-- 3. SEED DATA: Sample records for testing in Weeks 3-12
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
