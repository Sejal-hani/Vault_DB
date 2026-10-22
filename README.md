# VaultDB

### Enterprise Zero-Trust Database Security Middleware & Cryptographic Audit Ledger

> **Mathematically prove database access authenticity, enforce zero-trust access controls, and eliminate audit trail tampering.**

[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16%2B-blue?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![immudb](https://img.shields.io/badge/immudb-Cryptographic%20Merkle%20Ledger-green?logo=database)](https://immudb.io/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/Test%20Suite-160%20Passed-success)](tests/)
[![Compliance](https://img.shields.io/badge/Compliance-GDPR%20|%20HIPAA%20|%20PCI--DSS-orange)](#11-regulatory-compliance-mapping)

---

## Table of Contents

- [1. Product Overview](#1-product-overview)
- [2. Product Demonstration](#2-product-demonstration)
- [3. System Architecture & Dual-Storage Engine](#3-system-architecture--dual-storage-engine)
- [4. Core Capabilities](#4-core-capabilities)
- [5. Threat Model & Defense Matrix](#5-threat-model--defense-matrix)
- [6. Security Workstation Web Console](#6-security-workstation-web-console)
- [7. Installation & Setup Guide](#7-installation--setup-guide)
- [8. Enterprise Personas & Access Control](#8-enterprise-personas--access-control)
- [9. Automated Verification & Test Suite](#9-automated-verification--test-suite)
- [10. Python SDK Integration](#10-python-sdk-integration)
- [11. Regulatory Compliance Mapping](#11-regulatory-compliance-mapping)
- [12. Project Directory Structure](#12-project-directory-structure)

---

## 1. Product Overview

In regulated enterprise environments such as financial services, healthcare, and fintech, proving **who accessed what data, when, and under what authority** is both an operational imperative and a strict regulatory mandate.

Traditional database architectures remain vulnerable to three primary attack vectors:
1. **Insider Tampering**: Superusers and database administrators can alter, backdate, or delete rows directly from relational audit tables (`DELETE FROM audit_logs`).
2. **Client-Side Identity Spoofing**: Trusting client applications to declare their identity in SQL sessions invites privilege escalation and impersonation.
3. **Reconnaissance Blind Spots**: Denied access attempts, cross-tenant queries, and multi-statement SQL injection attempts are frequently omitted from forensic logging.

**VaultDB** functions as a high-performance, transparent security middleware proxy between client applications and database infrastructure. Every query is parsed at the AST level, evaluated under server-derived zero-trust identity, dynamically scoped to tenant boundaries, masked for sensitive PII, and committed simultaneously to an append-only [immudb](https://immudb.io/) cryptographic Merkle tree ledger and a [PostgreSQL](https://www.postgresql.org/) relational mirror.

---

## 2. Product Demonstration

[![Watch VaultDB Demonstration](https://img.youtube.com/vi/DEMO_VIDEO_ID/maxresdefault.jpg)](https://www.youtube.com/watch?v=DEMO_VIDEO_ID)

> *Video Walkthrough: Zero-trust query interception, cryptographic Merkle tree audit verification, real-time database tampering detection, and administrative security workstation.*

---

## 3. System Architecture & Dual-Storage Engine

### High-Level Architecture

```mermaid
flowchart TD
    subgraph Clients ["Client Applications"]
        UI["Web Management Console"]
        SDK["Python Client SDK"]
    end

    subgraph Middleware ["VaultDB Security Middleware"]
        Auth["Authentication & Identity"]
        Parser["AST SQL Parser & Firewall"]
        Policy["Policy Engine & Data Masking"]
        Engine["VaultEngine Orchestrator"]

        Auth --> Parser --> Policy --> Engine
    end

    subgraph Storage ["Dual-Storage Layer"]
        PG[("PostgreSQL<br/>Business DB & Audit Mirror")]
        Immu[("immudb<br/>Cryptographic Merkle Ledger")]
    end

    Clients -->|SQL Query| Auth
    Engine -->|Execute & Mirror| PG
    Engine -->|Cryptographic Seal| Immu
```

### Dual-Storage & Cryptographic Verification

```mermaid
flowchart LR
    subgraph DualCommit ["Synchronized Dual-Commit"]
        direction TB
        Engine["VaultEngine"]
        PG_Mirror[("PostgreSQL Mirror")]
        Immu_Tree[("immudb Merkle Tree")]

        Engine -->|Relational Record| PG_Mirror
        Engine -->|Cryptographic Append| Immu_Tree
    end

    subgraph Verification ["Tamper Verification"]
        direction TB
        Verifier["Cross-Verification Engine"]
        Status{"Integrity Match?"}
        Valid["Verified Untampered"]
        Tamper["Tamper Alert"]

        Verifier --> Status
        Status -->|Yes| Valid
        Status -->|No| Tamper
    end

    PG_Mirror -.->|Read Stored Hash| Verifier
    Immu_Tree -.->|Read Merkle Root| Verifier
```

VaultDB couples two complementary storage technologies:
1. **PostgreSQL Relational Mirror (`vault_audit.audit_logs`)**:
   - Stores fast, indexable relational records with B-tree indexes for dashboard search, pagination, and multi-field filtering.
   - Enforced by database-level triggers (`trg_no_update_delete_audit`) that reject `UPDATE`, `DELETE`, and `TRUNCATE` operations directly at the database engine.
2. **immudb Append-Only Merkle Ledger**:
   - Commits each audit log entry (`audit:log:{log_id}`) into an append-only Merkle tree.
   - Every write calculates a SHA-256 digest, advances the linear transaction height, and updates the state root hash.
   - Provides mathematical cryptographic inclusion proofs (`verifiedSet`, `verifiedGet`).
3. **Dual-Store Cross-Verification**:
   - When an audit record is verified, the middleware fetches both copies (PostgreSQL and immudb).
   - If an unauthorized out-of-band modification occurs in PostgreSQL, the Merkle root mismatch is detected immediately, displaying the altered fields side-by-side against the immudb root truth.

---

### Query Lifecycle & Execution Sequence

```mermaid
sequenceDiagram
    autonumber
    actor Client as Authenticated Client
    participant Auth as Auth & Identity Engine
    participant Engine as VaultEngine Middleware
    participant Policy as Policy & Anomaly Engine
    participant PG as PostgreSQL (Business DB)
    participant Immu as immudb (Cryptographic Ledger)

    Client->>Auth: Request + JWT Cookie / X-API-Key
    Auth->>Auth: Verify Signature & Derive Authenticated User + Role
    Client->>Engine: Execute SQL Query
    Engine->>Engine: Parse AST, extract actions, tables, sensitive columns
    Engine->>Policy: Evaluate RBAC permissions & multi-statement check

    alt Access Denied / Policy Violation
        Policy-->>Engine: Violation Detected (AccessDeniedError)
        Engine->>Policy: Evaluate Anomaly Rules (e.g. Repeated Denials)
        Engine->>Immu: append_audit_log(status="DENIED", anomalies)
        Engine->>PG: write_audit_log(status="DENIED", immudb_log_id)
        Engine-->>Client: 403 Forbidden + Human Explanation + Audit Reference
    else Access Authorized
        Policy-->>Engine: Authorized
        Engine->>Policy: Apply Row-Level Security (RLS query rewrite for Customer)
        Engine->>PG: Execute scoped query on ConnectionPool
        PG-->>Engine: Raw Result Set
        Engine->>Policy: Apply Dynamic Data Masking (SSN, Cards, Passwords)
        Engine->>Policy: Evaluate Anomalies (Bulk Exfiltration, After-Hours)
        Engine->>Immu: append_audit_log(status="SUCCESS", is_anomaly)
        Immu-->>Engine: Transaction ID + SHA-256 Merkle Root
        Engine->>PG: write_audit_log(status="SUCCESS", immudb_tx_id, immudb_tx_hash)
        Engine-->>Client: Masked Tabular Results + Cryptographic Ledger Receipt
    end
```

---

## 4. Core Capabilities

### Cryptographic Audit Ledger
* **Dual-Commit Pipeline**: Every query attempt (both successful executions and rejected violations) is recorded in PostgreSQL and committed to an append-only [immudb](https://immudb.io/) Merkle tree.
* **Mathematical Inclusion Proofs**: Each audit entry produces a verifiable SHA-256 state root and linear transaction height. Auditors can independently verify cryptographic membership proofs directly in the web console or via API.
* **Engine-Level Immutability**: PostgreSQL PL/pgSQL triggers in [`db/schema.sql`](db/schema.sql) reject direct `UPDATE`, `DELETE`, and `TRUNCATE` operations on `vault_audit.audit_logs`. If a DBA circumvents relational triggers out-of-band, the Merkle tree state in immudb flags the discrepancy with field-by-field verification diffs.

### Role-Based Access Control (RBAC) & AST Parser
* **Server-Derived Identity**: Client requests cannot dictate or override `app_user` or `user_role`. Identity is derived strictly server-side via RFC 7519 HS256 JWT tokens or cryptographically verified API keys in [`src/vault_db/auth/`](src/vault_db/auth/).
* **AST-Level SQL Inspection**: Deep parsing in [`src/vault_db/core/parser.py`](src/vault_db/core/parser.py) extracts targets, actions (`SELECT`, `INSERT`, `UPDATE`, `DELETE`, `DDL:DROP`, `ALTER`), and sensitive attributes before execution.
* **Injection Firewall**: Blocks stacked queries (multi-statement injection), CTE write attacks (`WITH x AS (DELETE ...) SELECT 1;`), `COPY PROGRAM`, and unprivileged privilege escalation (`SET ROLE`).

### Tenant Isolation via Row-Level Security (RLS)
* **Automatic Query Rewriting**: Customer queries are dynamically intercepted in [`src/vault_db/core/rls.py`](src/vault_db/core/rls.py) and constrained to personal account and transaction records at runtime.
* **Cross-Tenant Violation Guard**: Explicit customer attempts to query foreign account numbers (`ACC-...`) or arbitrary user records are blocked with an immediate security denial and recorded into the ledger.

### Dynamic In-Flight Data Masking
* **In-Flight PII Redaction**: Automatically redacts sensitive identifiers (Social Security Numbers as `***-**-XXXX`, credit card numbers, CVVs, and passwords) in query responses via [`src/vault_db/core/masking.py`](src/vault_db/core/masking.py).
* **Credential Secret Suppression**: Automatically strips security-critical credential columns (`password_hash`, `api_key`) from all tabular query results and Schema Explorer responses across all roles, preventing credential exfiltration while preserving server-side authentication.
* **Masked Audit Trails**: Constants in SQL text are sanitized in both execution results and persistent audit logs, preventing PII leakage into compliance archives.

### Behavioral Anomaly Detection Engine
* **Unusual Bulk Data Access**: Flags non-admin queries attempting to retrieve large row counts (`>= 1,000` rows) exceeding baseline operational thresholds.
* **Unusual After-Hours Access**: Flags employee or staff queries accessing sensitive customer financial records outside configured banking hours (`09:00 – 18:00 IST`). Customers accessing personal accounts 24/7 are exempt.
* **Repeated Unauthorized Access**: Accumulates failed access attempts in a sliding time window (`>= 2` denials within 5 minutes) and updates cumulative violation tracking with cross-references to the audit ledger.
* **Unusual Bulk Modification**: Flags high-impact `UPDATE` or `DELETE` statements affecting broad row sets (`>= 10` rows) without narrow primary key constraints.
* **Slack Webhook Dispatcher**: Dispatches real-time Slack Block Kit alerts via [`src/vault_db/core/alerts.py`](src/vault_db/core/alerts.py) when critical anomalies are detected.

### Just-in-Time (JIT) Temporary Privilege Elevation
* **Self-Service Requests**: Employees and auditors can request temporary elevation (e.g. 1h, 12h, 24h) with mandatory business justifications via [`src/vault_db/api/routes/approvals.py`](src/vault_db/api/routes/approvals.py).
* **Administrative Governance**: Administrators review, approve, reject, or immediately revoke active grants with one click.
* **Automated Expiration**: Active grants automatically expire after the granted window, reverting the user to baseline privileges.

### Audit-Grade Compliance PDF Reports
* **Filtered Audit Exports**: Compliance officers can generate certified PDF reports filtered by time range (24h, 7d, 30d, all time), user identity, role, and execution status using [`src/vault_db/reports/pdf_generator.py`](src/vault_db/reports/pdf_generator.py).
* **Cryptographic Evidence**: Reports include cryptographic state roots, transaction IDs, client IPs, execution durations, and tamper verification status suitable for regulatory audits.

---

## 5. Threat Model & Defense Matrix

| Threat Vector | Attack Scenario | VaultDB Defense Mechanism |
| :--- | :--- | :--- |
| **Rogue DBA / Insider Threat** | Attacker with database admin access executes `DELETE FROM audit_logs` or modifies past queries. | **immudb Merkle Tree**: Immutable append-only ledger prevents alterations. PostgreSQL triggers reject direct table mutations. In-browser verification flags field-by-field diffs if the relational store is tampered with. |
| **Client Identity Spoofing** | Adversary injects `{"user": "admin@bank.com"}` in query parameters. | **Server-Derived Identity**: User identity and permissions are resolved exclusively from cryptographic JWT signatures or API keys. Client declarations are ignored. |
| **Stacked SQL Injection** | Malicious input attempts `SELECT 1; DROP TABLE app_data.accounts;`. | **AST Multi-Statement Firewall**: Detects stacked statements and CTE write vectors; blocks execution before reaching PostgreSQL and logs a security violation. |
| **PII Data Exfiltration** | Employee attempts to query unmasked customer SSNs or card numbers. | **Dynamic Data Masking**: In-flight regex masking redacts sensitive tokens (`***-**-XXXX`) in query results and sanitizes SQL constants in audit logs. |
| **Cross-Tenant Snooping** | Retail customer attempts to query other customer account numbers. | **Row-Level Security (RLS)**: Enforces tenant boundary isolation by rewriting customer queries to filter on authenticated user ID only. |
| **Reconnaissance Probing** | Adversary probes non-existent tables or triggers repeated denials. | **Persistent Denial Auditing**: Every denial is sealed into the ledger; rapid repeated denials trigger behavioral security alerts. |

---

## 6. Security Workstation Web Console

VaultDB provides a unified dark-themed web workstation served at **`http://localhost:8000`**:

* **Top Telemetry Stats Bar**: 4 real-time security telemetry cards (Total audited queries, Policy violations blocked, Flagged sensitive queries, Active temporary grants) stretched across the workstation header for instant operational visibility.
* **1-Click User Identity Switching**: Seamless zero-friction persona switching between enterprise identities (Admin, Auditor, Employee, Customer) directly from the top navigation bar or the SQL Console persona bar without password entry forms.
* **SQL Execution Console**: Interactive query editor with keyboard shortcuts (`Ctrl+Enter`), preset compliance and attack scenarios, execution latency metrics, and tabular result sets rendered with clean Indian Standard Time (`YYYY-MM-DD HH:MM:SS IST`) timestamps.
* **Audit Ledger**: Complete historical query trail with multi-field search filtering, chronological sorting, and sticky pagination (`25`, `50`, `100`, `250` rows per page).
* **Mathematical Proof Verification Modal**: Click **Verify Proof** on any ledger entry to view cryptographic SHA-256 state roots, transaction IDs, linear transaction heights, and live Merkle inclusion proofs proving database immutability.
* **Schema Explorer**: Interactive table inspection and column structure discovery for PostgreSQL schemas with pagination, masked PII, and backend credential suppression (`password_hash`, `api_key` stripped; `status` omitted from `users` display).
* **Security Center**:
  - *Access Requests & Approvals*: Self-service temporary elevation submission, admin approval, and one-click revocation.
  - *Security Alerts*: Real-time feed of detected behavioral anomalies with direct links (`#<ID>`) to the corresponding ledger record.
* **Compliance Report Generator**: Direct PDF compliance generation with custom date windows (24h, 7d, 30d, all) and status filters.

---

## 7. Installation & Setup Guide

### System Prerequisites
| Component | Minimum Version | Notes |
| :--- | :--- | :--- |
| **Python** | 3.10+ (Recommended: 3.12) | Core middleware runtime |
| **PostgreSQL** | 14+ (Recommended: 16) | Underlying relational database |
| **immudb** | 1.5+ | Append-only cryptographic Merkle tree ledger |
| **Git** | 2.30+ | Source code version control |

---

### Step-by-Step Installation

#### 1. Clone Repository & Setup Virtual Environment
```bash
# Clone the repository
git clone https://github.com/Sejal-hani/Vault_DB.git
cd Vault_DB

# Create Python virtual environment
python -m venv venv

# Activate virtual environment
# Windows PowerShell:
.\venv\Scripts\Activate.ps1
# Linux / macOS:
# source venv/bin/activate

# Upgrade package manager and install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

#### 2. Environment Configuration (`.env`)
Copy the environment template from [`.env.example`](.env.example) and verify your local settings:
```bash
cp .env.example .env
```
Ensure connection settings in [`.env`](.env.example) match your local environment:
```ini
# PostgreSQL Relational Business Store
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=5432
POSTGRES_DB=vaultdb
POSTGRES_USER=vault_user
POSTGRES_PASSWORD=vault123

# PostgreSQL Admin (for DDL, schema, and trigger setup)
POSTGRES_ADMIN_USER=postgres
POSTGRES_ADMIN_PASSWORD=postgres

# immudb Cryptographic Ledger
IMMUDB_HOST=127.0.0.1
IMMUDB_PORT=3322
IMMUDB_USER=immudb
IMMUDB_PASSWORD=immudb
IMMUDB_DATABASE=defaultdb

# Security & Encryption Keys
SECRET_KEY=vlt_sec_8f93e2b10a4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60

# Anomaly Detection Baseline Thresholds
ANOMALY_BULK_QUERY_THRESHOLD=1000
ANOMALY_BULK_MUTATION_THRESHOLD=10
ANOMALY_CONSECUTIVE_DENIALS_THRESHOLD=2
ANOMALY_DENIAL_WINDOW_SECONDS=300
ANOMALY_BUSINESS_HOURS_START=9
ANOMALY_BUSINESS_HOURS_END=18
ANOMALY_TIMEZONE=Asia/Kolkata
```

#### 3. Initialize Database & Immutability Triggers
Run the automated initialization script in [`scripts/init_databases.py`](scripts/init_databases.py) to establish database schemas from [`db/schema.sql`](db/schema.sql), immutability triggers, and seed demo enterprise accounts:
```bash
python scripts/init_databases.py
```

#### 4. Start Services

##### Terminal 1: Start immudb Ledger
```powershell
# Windows
.\bin\immudb.exe --dir data/immudb --pgsql-server=true --pgsql-server-port=5433 --port=3322

# Linux / macOS
./bin/immudb --dir data/immudb --pgsql-server=true --pgsql-server-port=5433 --port=3322
```

##### Terminal 2: Start VaultDB Application Server
```bash
python server.py
```

##### Alternative: Docker Compose
If you prefer running services in containers using [`docker-compose.yml`](docker-compose.yml):
```bash
docker compose up -d
```

Open **`http://localhost:8000`** in your browser to access the live dashboard.

---

## 8. Enterprise Personas & Access Control

### Pre-Configured Demo Personas
VaultDB includes 4 pre-seeded enterprise banking personas available for instant 1-click identity switching in the dashboard:

| Role | Email Identity | Default Password | API Key | Permissions |
| :--- | :--- | :--- | :--- | :--- |
| **Admin** | `admin@bank.com` | `AdminPass123!` | `vlt_key_admin_9a8b7c6d5e4f3a2b` | Full read, write, DDL execution, access approvals, security alerts. |
| **Auditor** | `compliance.lead@bank.com` | `AuditorPass123!` | `vlt_key_auditor_5d6e7f8a9b0c1d2e` | Read-only ledger audit, proof verification, report generation, masked schema inspection. |
| **Employee** | `john@bank.com` | `EmployeePass123!` | `vlt_key_employee_1a2b3c4d5e6f7a8b` | Standard business transactions, temporary elevation requests, masked PII. |
| **Customer** | `alice@bank.com` | `CustomerPass123!` | `vlt_key_customer_4d5e6f7a8b9c0d1e` | Self-service banking, personal account access (RLS-scoped, masked PII). |

---

### Role-Based Access Control (RBAC) Matrix

| Resource / Action | Customer | Employee | Auditor | Admin |
| :--- | :---: | :---: | :---: | :---: |
| `accounts:SELECT` | Allowed (RLS Scoped + Masked) | Allowed (Masked) | Allowed (Masked) | Allowed (Full Access) |
| `accounts:INSERT/UPDATE/DELETE` | Denied | Denied | Denied | Allowed |
| `transactions:SELECT` | Allowed (RLS Scoped) | Allowed | Allowed | Allowed |
| `transactions:INSERT/UPDATE` | Denied | Allowed | Denied | Allowed |
| `transactions:DELETE` | Denied | Denied | Denied | Allowed |
| `users:SELECT` | Denied | Denied | Allowed (Secrets Stripped) | Allowed (Secrets Stripped) |
| `users:INSERT/UPDATE/DELETE` | Denied | Denied | Denied | Allowed |
| `audit_logs:SELECT` | Allowed (Own Scoped History) | Denied | Allowed (Full Ledger) | Allowed (Full Ledger) |
| `audit_logs:UPDATE/DELETE/TRUNCATE` | **Blocked by Trigger** | **Blocked by Trigger** | **Blocked by Trigger** | **Blocked by Trigger** |
| `DDL (DROP, ALTER, TRUNCATE)` | Denied | Denied | Denied | Allowed |

---

## 9. Automated Verification & Test Suite

VaultDB features an automated test suite containing **160 tests** in [`tests/`](tests/) covering adversarial vectors, cryptographic validation, and role enforcement:

```bash
pytest tests/ -v
```

### Test Coverage Highlights
* **100+ Adversarial SQL Vectors** ([`tests/test_attack_vectors.py`](tests/test_attack_vectors.py)): Multi-statement injection, CTE writes, `COPY PROGRAM`, `SET ROLE`, out-of-band schema drops, and comment truncation.
* **Engine Immutability Triggers**: Verification that direct `UPDATE`, `DELETE`, and `TRUNCATE` operations on `vault_audit.audit_logs` are rejected by PostgreSQL.
* **Cryptographic Merkle Proofs** ([`tests/test_immudb.py`](tests/test_immudb.py)): SHA-256 state root consistency and tamper detection logic.
* **Enterprise Security & Approvals** ([`tests/test_enterprise_security.py`](tests/test_enterprise_security.py)): Evaluation of bulk thresholds (`>= 1,000` rows), after-hours windows, repeated denial accumulation, temporary JIT elevation, PDF compliance export, credential secret suppression (`password_hash`, `api_key`), and non-admin SSN masking.
* **Tenant Isolation & Masking** ([`tests/test_rbac.py`](tests/test_rbac.py)): Customer row scoping and in-flight PII redaction.

---

## 10. Python SDK Integration

Applications connect to VaultDB using the Python client SDK:

```python
from src.vault_db import VaultClient

# 1. Initialize client using authenticated credentials
client = VaultClient(
    base_url="http://localhost:8000",
    email="alice@bank.com",
    password="CustomerPass123!"
)

# 2. Execute query (automatically scoped via RLS and masked for PII)
response = client.execute_query("SELECT * FROM app_data.accounts;")
print("Customer Accounts:", response["data"])

# 3. Retrieve cryptographic audit ledger entries
logs = client.get_audit_logs(limit=5)
print("Latest Log ID:", logs[0]["id"])

# 4. Verify cryptographic Merkle proof against immudb
proof = client.verify_proof(log_id=logs[0]["id"])
print("Cryptographically Verified:", proof["verified"])
```

---

## 11. Regulatory Compliance Mapping

* **GDPR Article 30 (Records of Processing Activities)**: Maintains an immutable, unalterable log of every query accessing personal customer data.
* **GDPR Article 15 (Right of Access / Subject Access Disclosure)**: Customers can view a certified audit of every internal employee, auditor, and automated service that accessed their personal records.
* **HIPAA §164.312(b) (Audit Controls)**: Implements hardware-enforced and cryptographically verifiable mechanisms that record and examine database activity.
* **PCI-DSS Requirement 10.2**: Automated audit trails for all administrative actions, access to cardholder data, and invalid logical access attempts.

---

## 12. Project Directory Structure

```
Vault_DB/
├── ARCHITECTURE.md                 # System architecture, data flow & security design
├── config/
│   ├── __init__.py
│   └── settings.py                     # Centralized Pydantic configuration & env validation
├── data/                               # Local persistent storage (immudb ledger & alerts buffer)
├── db/
│   └── schema.sql                      # Database DDL, triggers, and immutability procedures
├── docker-compose.yml                  # Multi-container orchestration (PostgreSQL, immudb, VaultDB)
├── Dockerfile                          # Production container image specification
├── pyproject.toml                      # PEP 621 package metadata & project build configuration
├── requirements.txt                    # Python runtime package dependencies
├── server.py                           # Application web server entry point
├── scripts/
│   ├── init_databases.py               # Database setup, schema generation & persona seeding
│   ├── seed_transactions.py            # High-volume transactional data generator
│   └── start_services.py               # Standalone daemon process launcher
├── src/
│   └── vault_db/
│       ├── __init__.py
│       ├── vault_client.py             # VaultDB Python Client SDK
│       ├── api/                        # FastAPI Web Layer
│       │   ├── app.py                  # Application factory, CORS, static mounting & lifecycle
│       │   ├── dependencies.py         # Shared engine singleton & serialization utilities
│       │   ├── models.py               # Pydantic request & response schemas
│       │   └── routes/                 # Modular Domain APIRouters
│       │       ├── __init__.py         # Router aggregation under /api prefix
│       │       ├── alerts.py           # Behavioral anomaly alert endpoints
│       │       ├── approvals.py        # Temporary privilege elevation workflow
│       │       ├── audit.py            # Audit ledger, Merkle proof verification & tables
│       │       ├── auth.py             # User login, persona demos, session lifecycle
│       │       └── query.py            # SQL query execution with zero-trust RBAC
│       ├── auth/                       # Security & Identity Modules
│       │   ├── dependencies.py         # Server-derived authentication dependencies
│       │   ├── jwt_handler.py          # RFC 7519 HS256 token encoding/decoding
│       │   └── security.py             # Security utilities & secret management
│       ├── core/                       # Core Security & Governance Engines
│       │   ├── alerts.py               # Slack Block Kit notification dispatcher
│       │   ├── anomaly.py              # Behavioral anomaly detector (bulk, off-hours, denials)
│       │   ├── approval.py             # Just-in-Time temporary elevation manager
│       │   ├── crypto.py               # AES-256-GCM column encryption utilities
│       │   ├── engine.py               # VaultEngine middleware orchestrator
│       │   ├── masking.py              # In-flight PII masking engine (SSN, cards, passwords)
│       │   ├── parser.py               # AST SQL inspection & injection firewall
│       │   ├── rbac.py                 # Role-based access control engine
│       │   └── rls.py                  # Row-level security dynamic query rewriter
│       ├── reports/                    # Compliance Reporting
│       │   └── pdf_generator.py        # Certified PDF compliance report generator
│       └── storage/                    # Database Connectors & Interfaces
│           ├── immudb_vault.py         # Append-only Merkle ledger interface
│           └── postgres.py             # PostgreSQL ConnectionPool interface
├── static/                             # Frontend Web Console Assets
│   ├── css/
│   │   └── style.css                   # Enterprise dark-themed workstation stylesheet
│   └── js/
│       └── app.js                      # Modular single-page application client logic
├── templates/
│   └── index.html                      # Security workstation management interface
└── tests/                              # Comprehensive Automated Test Suite
    ├── test_api.py                     # REST API integration tests
    ├── test_attack_vectors.py          # 100+ Adversarial SQL injection & exploit tests
    ├── test_enterprise_security.py     # Enterprise RBAC, RLS, JIT approvals & PDF tests
    ├── test_immudb.py                  # Cryptographic Merkle verification tests
    └── test_rbac.py                    # Role-based access control permission tests
```
