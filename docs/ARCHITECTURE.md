# VaultDB: System Architecture & Design Specification

## 1. Executive Summary

**VaultDB** is a lightweight database middleware, access control, and immutable audit logging system designed for **PostgreSQL**. Its primary objective is to fulfill compliance audit requirements (such as **GDPR Article 30** and **HIPAA §164.312**) by answering the fundamental security question:

> *"Who accessed what data, which exact SQL query was executed, on which table, at what time, and how many rows were affected?"*

VaultDB achieves this by acting as a transparent proxy layer between application code and the database, capturing every statement, validating caller permissions against role-based access rules, flagging queries touching sensitive attributes (like SSNs or passwords), and persisting an append-only audit trail that cannot be updated or deleted by normal users.

---

## 2. The Core Problem: Why VaultDB?

### The Compliance Gap
In modern software architectures, applications connect to PostgreSQL using a single shared database connection pool with credentials such as `postgres` or `app_user`.

```
[User: Alice]   ──┐
[User: Bob]     ──┼──> [App Backend] ──(Single Connection: 'app_user')──> [PostgreSQL]
[User: Charlie] ──┘
```

When an audit or security investigation occurs:
1. **PostgreSQL Default Logs** only record the database username (`app_user`). PostgreSQL has no native awareness of whether Alice, Bob, or Charlie initiated the request.
2. Standard logging does not capture the context of query results (e.g., number of rows returned/affected).
3. If an attacker or compromised internal user gains database credentials, they can modify or delete logs stored in standard database tables to erase evidence.

### What VaultDB Provides
VaultDB binds the **human application identity** to each database interaction, evaluates access authorization prior to execution, flags sensitive queries, and records an **immutable audit record** directly inside PostgreSQL.

---

## 3. High-Level System Architecture

```mermaid
flowchart TD
    subgraph Client Application
        AppCode["Application / API Code\n(e.g., user = 'sarah@company.com')"]
    end

    subgraph VaultDB Middleware Layer
        VClient["VaultDB Client / Wrapper"]
        RBAC["Access Control Engine\n(admin | writer | reader)"]
        SensDetect["Sensitive Query Detector\n(flags: ssn, password, credit_card)"]
        Timer["Execution Monitor\n(latency & row count)"]
    end

    subgraph PostgreSQL Database
        subgraph Schema: app_data
            AppTables["Business Tables\n(customers, orders, reports)"]
        end

        subgraph Schema: vault_audit
            AuditTable["vault_audit.audit_logs\n(APPEND-ONLY / IMMUTABLE)"]
            TriggerRule["Immutability Rule / Trigger\n(Rejects UPDATE & DELETE)"]
        end
    end

    AppCode -->|1. execute query with context| VClient
    VClient -->|2. Check permissions| RBAC
    RBAC -- Denied -->|Raise PermissionError & Log Attempt| VClient
    RBAC -- Allowed -->|3. Inspect SQL for sensitive fields| SensDetect
    SensDetect -->|4. Execute SQL via psycopg| AppTables
    AppTables -->|5. Return result set & count| Timer
    Timer -->|6. Write immutable audit entry| AuditTable
    AuditTable -.->|Guarded by| TriggerRule
    Timer -->|7. Return clean result to app| AppCode
```

---

## 4. Query Execution Flow (Step-by-Step)

Here is what happens under the hood for every single query:

1. **Invocation**: The application code calls `vault_client.execute(query, params, user, role)`.
2. **Access Control Check (Pre-execution)**:
   * VaultDB parses the query to determine the operation (`SELECT`, `INSERT`, `UPDATE`, `DELETE`) and the target table(s).
   * It checks the role against the **Access Control Matrix**.
   * If unauthorized, the query is **blocked immediately**. A security violation log entry is recorded, and an exception is raised.
3. **Sensitive Field Detection**:
   * The SQL statement is analyzed for keywords or columns marked as sensitive (e.g., `ssn`, `password`, `credit_card`, `secret`).
   * If detected, the query is flagged: `is_sensitive = TRUE`.
4. **Database Execution**:
   * VaultDB sends the query over the TCP/IP socket to PostgreSQL using the direct `psycopg` driver.
   * Execution time and affected/returned row counts are captured.
5. **Audit Logging (Atomic / Near-Atomic)**:
   * VaultDB inserts a new record into `vault_audit.audit_logs` containing:
     - Exact UTC timestamp (server-generated)
     - Application username
     - Assigned role
     - Target table(s)
     - SQL operation and full query text
     - Rows returned / affected
     - Sensitive flag status
     - Execution status (`SUCCESS` or `ERROR`)
6. **Result Returned**: The query results are returned to the caller exactly as a standard database cursor would return them.

---

## 5. Database Schema Design

To ensure a strict separation of concerns, VaultDB uses **two separate PostgreSQL schemas**:
1. `app_data`: Holds business tables (e.g., `customers`, `orders`).
2. `vault_audit`: Holds audit tables and immutability logic.

### 5.1 Business Schema (`app_data`)
```sql
CREATE SCHEMA IF NOT EXISTS app_data;

CREATE TABLE app_data.customers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    ssn VARCHAR(20),                -- Sensitive field
    credit_card VARCHAR(30),        -- Sensitive field
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE app_data.orders (
    id SERIAL PRIMARY KEY,
    customer_id INTEGER REFERENCES app_data.customers(id),
    amount DECIMAL(10, 2) NOT NULL,
    status VARCHAR(20) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

### 5.2 Audit Schema (`vault_audit`)
```sql
CREATE SCHEMA IF NOT EXISTS vault_audit;

CREATE TABLE vault_audit.audit_logs (
    log_id BIGSERIAL PRIMARY KEY,
    logged_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
    app_user VARCHAR(100) NOT NULL,
    user_role VARCHAR(20) NOT NULL,
    action VARCHAR(10) NOT NULL,              -- SELECT, INSERT, UPDATE, DELETE
    target_table VARCHAR(100) NOT NULL,
    query_text TEXT NOT NULL,
    rows_affected INTEGER DEFAULT 0,
    is_sensitive BOOLEAN DEFAULT FALSE,
    execution_status VARCHAR(20) NOT NULL,    -- SUCCESS, DENIED, ERROR
    error_message TEXT
);
```

---

## 6. Immutability Strategy & Honest Security Analysis

### How VaultDB Enforces Immutability
A compliance log is worthless if someone can alter previous records to hide an unauthorized data read or deletion. VaultDB secures the audit log through a **defense-in-depth approach**:

#### Layer 1: PostgreSQL Privilege Separation (RBAC at DB level)
The application user connecting to PostgreSQL (`vault_app_user`) is granted:
* `SELECT`, `INSERT`, `UPDATE`, `DELETE` on `app_data.*`
* `SELECT`, `INSERT` on `vault_audit.audit_logs`
* **NO `UPDATE`, `DELETE`, or `TRUNCATE`** on `vault_audit.audit_logs`

```sql
REVOKE UPDATE, DELETE, TRUNCATE ON vault_audit.audit_logs FROM vault_app_user;
```

#### Layer 2: PostgreSQL Engine-Level Rules / Trigger Guards
Even if someone attempts an `UPDATE` or `DELETE`, a trigger function or PostgreSQL rule intercepts the command and raises an exception:

```sql
CREATE OR REPLACE FUNCTION vault_audit.prevent_log_tampering()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'VaultDB Security Violation: Audit records in vault_audit.audit_logs are immutable and cannot be updated or deleted.';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_immutable
BEFORE UPDATE OR DELETE ON vault_audit.audit_logs
FOR EACH ROW EXECUTE FUNCTION vault_audit.prevent_log_tampering();
```

### Honest Security Disclosure (Threat Model Limitations)

| Threat Scenario | Protected? | Explanation |
| :--- | :---: | :--- |
| **Application user runs `UPDATE audit_logs`** | ✅ **YES** | Blocked by PostgreSQL permissions and trigger. |
| **Application user runs `DELETE FROM audit_logs`** | ✅ **YES** | Blocked by PostgreSQL permissions and trigger. |
| **Application user runs `TRUNCATE audit_logs`** | ✅ **YES** | Blocked by `REVOKE TRUNCATE`. |
| **Compromised application backend code** | ✅ **YES** | Backend cannot modify past records even if hijacked. |
| **PostgreSQL Superuser (`postgres` admin)** | ⚠️ **NO** | A database superuser has full administrative control to disable triggers or drop tables. |

> **V1 Security Boundary**: VaultDB enforces strict immutability against **all application users, developers, and standard database roles**. In a database, a superuser (`postgres`) always has administrative authority over the database engine itself. (In V2, we can add cryptographic hash chaining so that any manual modification by an administrator is immediately detectable).

---

## 7. Access Control Model

VaultDB implements a clear, 3-tier Role-Based Access Control (RBAC) model:

| Role | Permitted Operations | Permitted Tables | Example Persona |
| :--- | :--- | :--- | :--- |
| **`admin`** | `SELECT`, `INSERT`, `UPDATE`, `DELETE` | All tables (`customers`, `orders`, etc.) | System Administrator |
| **`writer`** | `SELECT`, `INSERT`, `UPDATE` (No `DELETE`) | Assigned operational tables (`orders`) | Data Entry / Staff |
| **`reader`** | `SELECT` only (Strictly Read-Only) | Assigned tables | Auditor / Reporting User |

### Enforcement Point
Enforcement happens **before** the query is passed to the database. If a `reader` attempts:
```sql
DELETE FROM app_data.customers WHERE id = 1;
```
VaultDB rejects the query at the middleware stage, records an audit entry with `execution_status = 'DENIED'`, and raises a Python `PermissionError`.

---

## 8. Existing Database Features vs. VaultDB

| Feature | PostgreSQL Native Tool | What It Does | Why VaultDB Is Needed |
| :--- | :--- | :--- | :--- |
| **Query Logging** | `log_statement = 'all'` | Logs SQL queries to flat text files on disk on the DB server. | Native logs lack application-level human context (e.g. Alice vs Bob). Server text logs are hard to query in real-time via a web dashboard. |
| **Detailed Auditing** | `pgaudit` extension | A C-based extension that logs granular sessions and object audits. | Requires superuser installation, server configuration reboots, outputs to syslog/files, and does not provide an application-facing dashboard or unified middleware access control. |
| **Access Control** | PostgreSQL `GRANT / REVOKE` | Standard SQL object permission system. | Operates per database user. When web apps use a single pooled DB user, PostgreSQL cannot differentiate between the human users of the web app. VaultDB bridges this gap. |
| **Row-Level Security** | PostgreSQL `RLS` | Filters rows returned based on current session variables. | Excellent for multi-tenant row filtering, but does not provide end-to-end audit logging or user-level query metadata by default. |

---

## 9. Viva & Oral Exam Preparation

#### Q1: "Is VaultDB a database itself?"
**Answer:** No. VaultDB is a database middleware, access control, and auditing layer built on top of PostgreSQL. It sits between client applications and PostgreSQL to intercept, inspect, authorize, execute, and log queries.

#### Q2: "PostgreSQL already logs queries. Why did you build VaultDB?"
**Answer:** PostgreSQL logs queries to text files on the server using database role credentials (e.g., `app_user`). In web applications, all human users share that single connection. PostgreSQL has no concept of *which application user* (e.g., Sarah vs John) executed the query. Furthermore, server text logs are not easily queried, filtered, or protected by relational immutability triggers.

#### Q3: "What makes your audit log immutable?"
**Answer:** Two layers: First, `REVOKE UPDATE, DELETE, TRUNCATE` strips modification privileges from the application database role. Second, a PostgreSQL `BEFORE UPDATE OR DELETE` trigger aborts any modification attempts with an exception.

#### Q4: "Can a PostgreSQL superuser alter the audit log?"
**Answer:** Yes. A database superuser (`postgres`) has supreme authority to disable triggers or alter permissions. VaultDB secures against all application users and normal database roles, but true protection against a rogue DBA would require shipping logs to an external, write-only physical storage system.

#### Q5: "What is the difference between Authentication and Authorization in VaultDB?"
**Answer:** Authentication verifies *who* the user is (e.g. `sarah@company.com`). Authorization determines *what* they are allowed to do (e.g. Can role `writer` execute a `DELETE` on the `customers` table?). VaultDB focuses on **authorization** and **auditing**.
