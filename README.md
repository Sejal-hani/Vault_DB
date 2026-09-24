# VaultDB

> **Audit Logging & Access Control Middleware for PostgreSQL**  
> Designed to meet compliance requirements such as GDPR (Art. 30) and HIPAA (§164.312) by answering:  
> *"Who accessed what data, what exact SQL query was run, and when?"*

---

## Overview

VaultDB is a lightweight database middleware layer and compliance auditing tool. It sits transparently between your application code and a PostgreSQL database.

### Core Capabilities (V1 Scope)
1. **Query Logging Middleware**: Intercepts queries, captures human application identity (`app_user`), timestamp, exact query, target tables, and rows affected.
2. **Immutable Audit Trail**: Audit records in `vault_audit.audit_logs` are protected from modification or deletion via database permissions and PostgreSQL engine-level triggers.
3. **Role-Based Access Control (RBAC)**: Enforces access policies for 3 roles:
   - `admin`: Full access across all tables.
   - `writer`: Can read and insert/update assigned operational tables.
   - `reader`: Read-only (`SELECT`) on assigned tables.
4. **Sensitive Query Detection**: Flags queries touching sensitive fields (e.g., `ssn`, `password`, `credit_card`).
5. **Audit Dashboard & Reports**: Inspect, filter, and export audit trails to PDF for compliance reviews.

---

## Documentation & Architecture

* Detailed architectural specifications, schema designs, data flows, and viva questions can be found in **[ARCHITECTURE.md](ARCHITECTURE.md)**.
* Project requirements and timeline are documented in **[vault_db.txt](vault_db.txt)**.

---

## Setup & Development (Week 1)

### Requirements
* Python 3.12+
* PostgreSQL 16+
* `psycopg` (v3)

### Installation & Setup
1. Create and activate a Python virtual environment:
   ```bash
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Initialize the database schemas and sample data:
   ```bash
   psql -U postgres -d postgres -f schema.sql
   ```

---

## Quickstart & Usage Example

```python
from vault_client import VaultClient

# 1. Initialize client
client = VaultClient()

# 2. Execute a query with user context
results = client.execute(
    query="SELECT name, email FROM app_data.customers WHERE id = %s",
    params=(1,),
    app_user="sarah@company.com",
    user_role="writer"
)
print("Query Results:", results)

# 3. Retrieve latest audit logs recorded in PostgreSQL
logs = client.get_audit_logs(limit=5)
for log in logs:
    print(log)

client.close()
```