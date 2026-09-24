# VaultDB: Complete Line-by-Line Code Explainer & Python Master Guide

This document explains every single file, function, line of code, keyword, and concept in VaultDB. Use this to understand the entire system and explain it with complete confidence.

---

# Table of Contents
1. [Python Fundamentals & Keywords Glossary](#1-python-fundamentals--keywords-glossary)
2. [Line-by-Line Breakdown: `vault_client.py`](#2-line-by-line-breakdown-vault_clientpy)
3. [Line-by-Line Breakdown: `schema.sql`](#3-line-by-line-breakdown-schemasql)
4. [Line-by-Line Breakdown: `init_db.py`](#4-line-by-line-breakdown-init_dbpy)
5. [Line-by-Line Breakdown: `test_query.py`](#5-line-by-line-breakdown-test_querypy)
6. [Top Viva Questions & 1-Sentence Answers](#6-top-viva-questions--1-sentence-answers)

---

# 1. Python Fundamentals & Keywords Glossary

| Keyword / Symbol | What it actually means | Why we use it here |
| :--- | :--- | :--- |
| `import re` | Python's built-in **Regular Expressions** module. | Used to search and extract SQL verbs and table names from query strings. |
| `import psycopg` | PostgreSQL database driver library for Python. | Translates Python commands into network packets and sends them to PostgreSQL. |
| `class` | A blueprint / template for creating objects. | `VaultClient` wraps all database logic into a single reusable object. |
| `def` | Defines a function (a block of reusable code). | Used to create helper functions like `extract_action()` and `execute()`. |
| `self` | Represents the specific instance of the class. | Allows methods inside `VaultClient` to access `self.conn` and `self.dbname`. |
| `__init__` | The "constructor" method that runs automatically when you create `VaultClient()`. | Connects to PostgreSQL as soon as `client = VaultClient()` is called. |
| `try ... except ... finally` | Error handling structure. | `try` runs the query, `except` catches errors, and `finally` **always runs** to guarantee the audit log is saved. |
| `with ... as cur:` | Context manager. | Automatically opens and closes database cursors cleanly without memory leaks. |
| `%s` | Parameter placeholder for SQL queries. | Prevents SQL injection by keeping data values separate from SQL commands. |
| `raise PermissionError(...)` | Stops execution and throws an explicit access error. | Blocks unauthorized users (like a `reader` trying to `DELETE`). |
| `Set` (`{...}`) | A collection of unique items with $O(1)$ fast lookup. | Used for `SENSITIVE_KEYWORDS` so checking `if word in SENSITIVE_KEYWORDS` is instantaneous. |

---

# 2. Line-by-Line Breakdown: `vault_client.py`

### Part 1: Imports and Security Definitions
```python
import re
import psycopg
```
* **Line 1 (`import re`):** Imports the Regular Expressions module for text pattern matching.
* **Line 2 (`import psycopg`):** Imports the official PostgreSQL database driver.

```python
SENSITIVE_KEYWORDS = {"ssn", "credit_card", "password", "secret", "cvv"}
SENSITIVE_TABLES = {"customers"}
PROTECTED_TABLES = {"audit_logs"}
```
* **`SENSITIVE_KEYWORDS`:** A Python `set` of column names that contain private personal/financial information. If any query mentions these, it gets flagged for GDPR/HIPAA compliance.
* **`SENSITIVE_TABLES`:** Tables that contain personal data. If someone runs `SELECT * FROM customers`, it is flagged as sensitive.
* **`PROTECTED_TABLES`:** System tables (`audit_logs`) that ordinary users cannot touch directly.

```python
ROLE_PERMISSIONS = {
    "admin": {"SELECT", "INSERT", "UPDATE", "DELETE"},
    "writer": {"SELECT", "INSERT", "UPDATE"},
    "reader": {"SELECT"}
}
```
* **`ROLE_PERMISSIONS`:** The Role-Based Access Control (RBAC) Matrix dictionary:
  - `admin`: Full permissions on all CRUD operations.
  - `writer`: Can read and modify operational data (`SELECT`, `INSERT`, `UPDATE`), but strictly forbidden from `DELETE`.
  - `reader`: Read-only (`SELECT`).

```python
SQL_RESERVED = {"select", "from", "where", "join", "into", "table", "update", "set", "values", "delete"}
```
* **`SQL_RESERVED`:** Standard SQL keywords. When extracting table names, we ignore these words so they aren't mistaken for tables.

---

### Part 2: Query Helper Functions

#### 1. Extracting the SQL Action
```python
def extract_action(query: str) -> str:
    q = query.strip().upper()
    for verb in ["DROP", "TRUNCATE", "ALTER", "CREATE", "DELETE", "UPDATE", "INSERT", "SELECT"]:
        if q.startswith(verb) or f" {verb} " in q or f"({verb} " in q:
            if verb in ["DROP", "TRUNCATE", "ALTER", "CREATE"]:
                return f"DDL:{verb}"
            return verb
    return "UNKNOWN"
```
* **`q = query.strip().upper()`:** Removes leading/trailing spaces and converts the query to uppercase for case-insensitive matching.
* **`for verb in [...]`:** We check destructive commands (`DROP`, `DELETE`, `UPDATE`) **first**. Why? If a query is `WITH d AS (DELETE FROM customers) SELECT * FROM d`, checking `DELETE` first prevents the user from hiding a delete inside a select.
* **`return f"DDL:{verb}"`:** Returns DDL commands with a prefix so `check_authorization()` can easily block non-admins.

#### 2. Extracting Target Tables
```python
def extract_tables(query: str) -> list:
    tables = set()
    q = query.lower()
    matches = re.finditer(r'\b(from|into|update|table|join)\s+([a-zA-Z0-9_.]+)', q)
    for m in matches:
        table_name = m.group(2).split('.')[-1]
        if table_name not in SQL_RESERVED:
            tables.add(table_name)
    return sorted(list(tables))
```
* **`r'\b(from|into|update|table|join)\s+([a-zA-Z0-9_.]+)'`:**
  - `\b`: Word boundary (matches whole words only).
  - `(from|into|update|table|join)`: The SQL keywords that introduce table names.
  - `\s+`: One or more whitespace spaces.
  - `([a-zA-Z0-9_.]+)`: Captures the table identifier (including schema qualification like `app_data.customers`).
* **`m.group(2).split('.')[-1]`:** Strips schema prefixes: `app_data.customers` becomes `customers`.
* **`return sorted(list(tables))`:** Returns a clean list of table names.

#### 3. Detecting Sensitive Queries (GDPR / HIPAA)
```python
def is_sensitive_query(query: str, tables: list = None) -> bool:
    q = query.lower()
    for word in SENSITIVE_KEYWORDS:
        if re.search(rf"\b{word}\b", q):
            return True
    if tables and "*" in q:
        for t in tables:
            if t in SENSITIVE_TABLES:
                return True
    return False
```
* **`re.search(rf"\b{word}\b", q)`:** Uses `\b` boundaries so the word `"assignment"` is **not** falsely flagged for containing `"ssn"`.
* **`if tables and "*" in q:`:** If the query is `SELECT * FROM customers`, it is flagged because `customers` contains sensitive columns (`ssn`, `credit_card`).

#### 4. Checking Role Authorization
```python
def check_authorization(user_role: str, action: str, tables: list) -> tuple:
    role = user_role.lower()

    if role not in ROLE_PERMISSIONS:
        return False, f"Unknown role: {user_role}"

    if action.startswith("DDL") and role != "admin":
        return False, f"Role '{user_role}' is not allowed to run DDL commands"

    if action not in ROLE_PERMISSIONS[role]:
        return False, f"Role '{user_role}' is not allowed to perform {action}"

    for t in tables:
        if t in PROTECTED_TABLES and role != "admin":
            return False, f"Role '{user_role}' cannot access system table '{t}'"

    return True, None
```
* **Step 1:** Verifies the role exists in `ROLE_PERMISSIONS`.
* **Step 2:** Blocks destructive DDL (`DROP`, `TRUNCATE`) for anyone who is not `admin`.
* **Step 3:** Checks if the user's role allows the requested action (e.g. `reader` performing `DELETE` ➔ Returns `False`).
* **Step 4:** Blocks direct client tampering with `audit_logs`.

---

### Part 3: The `VaultClient` Class
```python
class VaultClient:
    def __init__(self, host="127.0.0.1", port=5432, user="postgres", password="nimit8222", dbname="postgres"):
        self.dbname = dbname
        self.conn = psycopg.connect(
            host=host, port=port, user=user, password=password, dbname=dbname, autocommit=True
        )
```
* **`__init__`:** Connects directly to PostgreSQL on `127.0.0.1:5432` with `autocommit=True` (so audit logs and queries are committed immediately).

```python
    def execute(self, query: str, params=None, app_user="anonymous", user_role="reader"):
        action = extract_action(query)
        tables = extract_tables(query)
        target_str = ", ".join(tables) if tables else "unknown"
        is_sensitive = is_sensitive_query(query, tables)
```
* Parses the query and detects sensitivity before execution.

```python
        # 1. Check permissions
        allowed, reason = check_authorization(user_role, action, tables)
        if not allowed:
            self._log_audit(app_user, user_role, action, target_str, query, 0, is_sensitive, "DENIED", reason)
            raise PermissionError(f"Access Denied: {reason}")
```
* If unauthorized: Writes an audit record with `execution_status = "DENIED"` and raises `PermissionError`.

```python
        rows_affected = 0
        status = "SUCCESS"
        error_msg = None
        results = []

        try:
            with self.conn.cursor() as cur:
                cur.execute(query, params)
                if cur.description is not None:
                    results = cur.fetchall()
                    rows_affected = len(results)
                else:
                    rows_affected = cur.rowcount if cur.rowcount != -1 else 0
            return results
        except Exception as e:
            status = "ERROR"
            error_msg = str(e)
            raise e
        finally:
            self._log_audit(app_user, user_role, action, target_str, query, rows_affected, is_sensitive, status, error_msg)
```
* **`cur.description is not None`:** In Python DB API, `cur.description` is populated **only for queries that return rows (`SELECT`)**. If it's a `SELECT`, we call `cur.fetchall()`. If it's an `INSERT/UPDATE/DELETE`, we read `cur.rowcount`.
* **`finally:`:** **Guaranteed execution.** Whether the query succeeded, raised an error, or crashed, the `finally` block ALWAYS writes the audit trail into `vault_audit.audit_logs`.

---

# 3. Line-by-Line Breakdown: `schema.sql`

```sql
CREATE SCHEMA IF NOT EXISTS app_data;
CREATE SCHEMA IF NOT EXISTS vault_audit;
```
* Creates two independent database namespaces:
  - `app_data`: For operational business tables.
  - `vault_audit`: For security audit records.

```sql
CREATE TABLE IF NOT EXISTS app_data.customers (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    ssn VARCHAR(20),
    credit_card VARCHAR(30),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```
* **`SERIAL PRIMARY KEY`:** Auto-incrementing integer (1, 2, 3...) that uniquely identifies every customer.
* **`TIMESTAMP WITH TIME ZONE`:** Stores timestamps in UTC with timezone offset, preventing timezone ambiguity during compliance audits.

```sql
CREATE TABLE IF NOT EXISTS vault_audit.audit_logs (
    log_id BIGSERIAL PRIMARY KEY,
    logged_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
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
```
* **`BIGSERIAL`:** 64-bit integer supporting up to 9 quintillion log entries without overflowing.
* **`TEXT`:** Stores the entire SQL query string without character limits.

### Immutability Trigger in PL/pgSQL
```sql
CREATE OR REPLACE FUNCTION vault_audit.enforce_audit_immutability()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP IN ('UPDATE', 'DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'Audit logs cannot be updated, deleted, or truncated.';
    END IF;

    NEW.logged_at := CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
```
* **`TG_OP`:** A special PostgreSQL trigger variable containing the operation name (`'INSERT'`, `'UPDATE'`, `'DELETE'`, `'TRUNCATE'`).
* **`RAISE EXCEPTION`:** Aborts the transaction immediately with a fatal security error if anyone tries to modify or delete logs.
* **`NEW.logged_at := CURRENT_TIMESTAMP;`:** Overwrites the inserted timestamp with the PostgreSQL server's real clock, preventing attackers from forging historical timestamps.

---

# 4. Line-by-Line Breakdown: `init_db.py`

```python
import psycopg

def initialize_database():
    with open("schema.sql", "r", encoding="utf-8") as f:
        schema_sql = f.read()

    with psycopg.connect(
        host="127.0.0.1", port=5432, user="postgres", password="nimit8222", dbname="postgres", autocommit=True
    ) as conn:
        with conn.cursor() as cur:
            cur.execute(schema_sql)
```
* **`with open("schema.sql", "r") as f:`** Reads the SQL schema definition file into memory.
* **`psycopg.connect(...)`** Connects to PostgreSQL and executes all table creation and trigger commands in one step.

---

# 5. Line-by-Line Breakdown: `test_query.py`

```python
from vault_client import VaultClient

def run_test():
    client = VaultClient()

    current_user = "sarah@company.com"
    current_role = "writer"
    sql_query = "SELECT id, name, email FROM app_data.customers;"

    # 1. Execute query
    results = client.execute(
        query=sql_query,
        app_user=current_user,
        user_role=current_role
    )
    print("Query Results:", results)

    # 2. View latest audit log
    logs = client.get_audit_logs(limit=1)
    print("Latest Audit Log:", logs[0])
```
* Simple testing script where you can change `current_user`, `current_role`, and `sql_query` to test any query and see the live audit log immediately.

---

# 6. Top Viva Questions & 1-Sentence Answers

### Q1: What is VaultDB?
> *"VaultDB is an audit logging and access control database middleware that sits between applications and PostgreSQL to record an immutable query history for GDPR/HIPAA compliance."*

### Q2: Why is Python needed if we already have PostgreSQL?
> *"PostgreSQL only sees a single shared database connection user (`postgres`); Python is needed as the middleware to identify the human application user (`sarah@company.com`) and enforce role permissions before queries execute."*

### Q3: How do you make the audit log truly immutable?
> *"We use a PostgreSQL PL/pgSQL BEFORE trigger on `vault_audit.audit_logs` that raises an exception if anyone tries to run `UPDATE`, `DELETE`, or `TRUNCATE`."*

### Q4: How does Role-Based Access Control (RBAC) work?
> *"We have 3 roles: `admin` has full CRUD permissions, `writer` can read and insert/update operational data, and `reader` is strictly read-only (`SELECT`). Unauthorized actions are blocked with a `PermissionError`."*

### Q5: Why is the audit log written in a `finally` block?
> *"To guarantee 100% audit logging reliability—even if the SQL query fails with a database error or syntax exception, the `finally` block always executes and saves the attempt."*
