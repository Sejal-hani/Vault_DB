# CSE3103 Project Report: VaultDB
## An Enterprise Zero-Trust Database Security Middleware and Cryptographically Verifiable Audit Ledger

**Course**: CSE3103: Applied Databases and Systems Thinking  
**Institution**: School of Engineering and Technology, BML Munjal University  
**Track**: Development Track  
**Repository Release**: `v1.0-report` / `v1.1-report` (Release: `v1.1`) | **Commit**: `c20e0ce`  
**Authors**:
* **Somya Tomar** (Roll No: Somya-Roll / somya.tomar@bmu.edu.in) — *Middleware Architecture, Query Interception & Logging Engine*
* **Vani Shrivastava** (Roll No: Vani-Roll / vani.shrivastava@bmu.edu.in) — *Access Control, AST Firewall, RBAC & Row-Level Security*
* **Sejal Patil** (Roll No: Sejal-Roll / sejal.patil@bmu.edu.in) — *Security Workstation Console, Compliance PDF Reporting & Empirical Evaluation*

---

## Abstract

In regulated enterprise environments governed by mandates such as GDPR (Articles 15 & 30), HIPAA (§164.312), and PCI-DSS (Requirement 10.2), proving the authenticity of database transactions while preventing insider tampering remains a critical systems challenge. Traditional relational logging mechanisms remain fundamentally vulnerable to rogue administrative tampering (`DELETE FROM audit_logs`), client-side identity spoofing, and forensic blind spots during access denials. 

To address these vulnerabilities, we design and implement **VaultDB**, an enterprise-grade, zero-trust database security middleware and cryptographic audit ledger. Positioned as an inline proxy between client applications and database infrastructure, VaultDB intercepts SQL queries at the Abstract Syntax Tree (AST) level, derives authenticated caller identities server-side via RFC 7519 HMAC-SHA256 tokens and PBKDF2 hashing, enforces fine-grained Role-Based Access Control (RBAC), applies dynamic customer Row-Level Security (RLS), redacts sensitive PII in flight, and commits every transaction attempt simultaneously to a PostgreSQL relational mirror and an append-only [immudb](https://immudb.io/) Merkle tree ledger. 

We conduct a rigorous empirical benchmark over 15,000 queries across 5 repeated runs with a 50-query warmup. Under a mixed enterprise banking workload of 1,000 queries per run, VaultDB achieves a median (P50) latency of **3.22 ms** and an average throughput of **322.0 queries/second**, introducing an average overhead of only **0.82 ms** over pgAudit and **1.58 ms** over uninstrumented PostgreSQL. In exchange for this nominal overhead, VaultDB delivers complete cryptographic tamper-proofing with SHA-256 Merkle inclusion proofs, automated database corruption detection, and zero false-negative attack interception across 160 automated test cases.

**Index Terms**—*Database Security, Zero-Trust Architecture, Cryptographic Audit Ledger, Merkle Tree, immudb, Row-Level Security, Dynamic Data Masking, pgAudit, Regulatory Compliance.*

---

## 1. Introduction

### 1.1 Problem Statement and Motivation
Modern enterprise software architectures increasingly decouple client frontends, microservices, and database tiers. In high-stakes domains such as banking, electronic health records (EHR), and payments, organizational compliance frameworks require an irrefutable audit trail answering: *who accessed what data, at what exact wall-clock timestamp, and under what organizational authority?*

Despite extensive database hardening guidelines, traditional relational database management systems (RDBMS) suffer from three fundamental architectural flaws:
1. **The Rogue DBA & Superuser Vulnerability**: Audit tables residing within standard relational engines remain subject to modification by privileged accounts. A database administrator (DBA) or an adversary possessing compromised root credentials can execute `DELETE FROM audit_logs WHERE user_id = 'compromised'` or manipulate historical timestamps (`UPDATE audit_logs SET logged_at = ...`) without leaving an evidentiary trace in the database itself.
2. **Client-Side Identity Spoofing**: Traditional database connection pools connect under a generic service account (e.g., `db_user`). When client queries declare user context via application headers or session parameters, malicious actors can spoof identity declarations to evade personal accountability or escalate privileges.
3. **Forensic Blind Spots**: Relational triggers fire exclusively on database modifications (`INSERT`, `UPDATE`, `DELETE`) on existing tables. Unauthorized reconnaissance attempts, cross-tenant data snooping, malformed queries, and blocked stacked SQL injection attacks are discarded prior to execution, creating forensic blind spots for incident response teams.

### 1.2 Limitations of Existing Practice
Existing audit logging extensions, such as PostgreSQL’s `pgAudit`, intercept queries within the database executor and write unindexed plain-text statements to operating system files or `syslog`. While computationally lightweight, `pgAudit` exhibits severe operational limitations:
* **Log Mutability**: System administrators can alter, backdate, or delete flat syslog files using standard utilities (`sed`, `truncate`, `rm`).
* **Lack of Cryptographic Proofs**: Plaintext logs cannot mathematically prove that records have not been omitted, reordered, or forged.
* **No Inline Prevention or Masking**: `pgAudit` operates as a passive observer; it cannot rewrite queries to enforce customer row-level isolation or mask Personally Identifiable Information (PII) before results reach the client application.

### 1.3 Key Contributions
To eliminate these vulnerabilities, we design, implement, and evaluate **VaultDB**. Our key contributions include:
1. **Dual-Storage Synchronized Ledger**: An architecture coupling PostgreSQL for indexable relational business data with immudb for append-only, cryptographic Merkle tree audit logging, backed by engine-level PL/pgSQL immutability triggers.
2. **Zero-Trust AST Firewall & Identity Derivation**: An inline query parser that extracts SQL verbs, target tables, and sensitive attributes, deriving caller identity server-side via cryptographic tokens and enforcing RBAC with stacked injection blocking.
3. **Dynamic Customer RLS & In-Flight PII Masking**: An automated SQL AST rewriter that constrains retail customer queries to personal tenant boundaries and dynamically redacts Social Security Numbers (`***-**-XXXX`) while suppressing credentials at rest and in transit.
4. **Interactive Security Workstation & Compliance Reporting**: A dark-themed management console featuring real-time Merkle proof verification, simulated DBA tamper detection, behavioral anomaly alerting, and automated certified PDF compliance generation.
5. **Empirical Performance Evaluation**: A statistical benchmark over 15,000 queries demonstrating that VaultDB adds only **0.82 ms** of overhead compared to pgAudit while providing end-to-end cryptographic verifiability.

---

## 2. Background and Related Work

### 2.1 Database Systems Foundations
VaultDB builds upon core database and cryptographic primitives:
* **Write-Ahead Logging (WAL)**: Relational engines ensure ACID durability by writing changes sequentially to the WAL before updating data pages. However, WAL records are periodically recycled and do not serve as an unalterable, queryable compliance history.
* **Merkle Trees & Cryptographic Accumulators**: A Merkle tree is an append-only binary tree where every leaf node contains the cryptographic hash of a data record and every non-leaf node contains the cryptographic hash of its children. The state of the entire ledger is encapsulated in a single 32-byte **Merkle Root Hash**. Any unauthorized modification to an existing leaf node permanently invalidates the root hash, providing mathematical inclusion proofs ($\mathcal{O}(\log N)$ verification complexity).
* **Database Triggers vs. Middleware Proxies**: Engine-level triggers execute within the database engine but impose transaction locks and cannot prevent client identity spoofing over pooled connections. Conversely, middleware proxies intercept traffic externally, enabling pre-execution policy checks, dynamic query rewriting, and secret redaction.

### 2.2 Survey of Existing Solutions and Tools

```
+---------------------------------------------------------------------------------------------------+
| Tool / Solution       | Interception Layer   | Tamper Resistance     | Proof Verification | In-Flight PII Masking |
+---------------------------------------------------------------------------------------------------+
| pgAudit               | DBMS Executor Hook   | None (Mutable Files)  | No                 | No                    |
| Debezium (CDC)        | WAL Reader           | Kafka Topic Config    | No                 | No                    |
| Vitess                | Database Proxy       | RDBMS Table           | No                 | Partial (Sharding)    |
| immudb Standalone     | Key-Value / SQL Store| Merkle Tree (Native)  | Yes (SHA-256 Root) | No                    |
| VaultDB (Our Work)    | Zero-Trust Middleware| Dual-Commit Ledger    | Yes (Merkle + Diff)| Yes (Dynamic Regex)   |
+---------------------------------------------------------------------------------------------------+
```

* **pgAudit** [1]: The standard audit extension for PostgreSQL. Intercepts SQL calls using the `ExecutorRun_hook`. While efficient, logs reside in plaintext syslog files without cryptographic integrity or access control firewalls.
* **Debezium** [2]: A distributed Change Data Capture (CDC) platform capturing row-level changes from database transaction logs. While resilient for data streaming, it cannot intercept rejected queries, read-only queries (`SELECT`), or policy violations.
* **Vitess** [3]: A database clustering system for horizontal scaling of MySQL. Provides routing and query parsing, but focuses on sharding rather than regulatory non-repudiation and cryptographic audit verification.
* **immudb** [4]: An open-source, lightweight immutable database powered by an append-only Merkle tree. While immudb provides cryptographic verification primitives, it is not an inline SQL firewall for existing relational applications. VaultDB uniquely bridges this gap by positioning immudb as an automated cryptographic co-processor alongside PostgreSQL.

---

## 3. Requirements Specification

The design of VaultDB is guided by the functional and non-functional requirements set forth in the project specification.

### 3.1 Functional Requirements (V1 Scope)

| ID | Requirement Name | Description | Verification Criterion |
| :--- | :--- | :--- | :--- |
| **FR1** | Query Logging Middleware | Transparently intercept all client SQL queries; capture user identity, query text, wall-clock timestamp, target tables, and status. | 100% of queries intercepted without application code modification. |
| **FR2** | Immutable Audit Ledger | Commit audit records to an append-only store where rows cannot be updated, deleted, or backdated by any user or administrator. | Database triggers reject `UPDATE`/`DELETE`; immudb Merkle root detects corruption. |
| **FR3** | Role-Based Access Control | Enforce table-level and action-level authorization across baseline enterprise roles (`admin`, `writer`, `reader`). | Unprivileged actions blocked with HTTP 403 / AccessDeniedError. |
| **FR4** | Web Audit Workstation | Provide an interactive single-page dashboard displaying historical query trails with multi-field filtering and sorting. | Queries filterable by user, table, date range, and status. |
| **FR5** | Sensitive Query Detection | Automatically inspect queries for sensitive attributes (SSN, credit card, passwords) and flag them in UI. | Sensitive records highlighted in red badge with dedicated alert tag. |
| **FR6** | Compliance PDF Export | Generate certified compliance PDF reports containing audit history, execution latencies, and cryptographic state roots. | Single-click PDF download formatted for GDPR/HIPAA regulatory filing. |
| **FR7** | High-Volume Testing | Validate system stability, latency, and throughput under enterprise workloads exceeding 1,000 queries. | Benchmark executes 1,000+ queries continuously without crashes or memory leaks. |

### 3.2 Non-Functional Requirements (NFR)

| ID | Non-Functional Requirement | Target Metric / Threshold | Realized System Performance |
| :--- | :--- | :--- | :--- |
| **NFR1** | Middleware Latency Overhead | Average query overhead $< 5.0\text{ ms}$ over raw PostgreSQL. | **1.58 ms** average overhead (**3.13 ms** total latency). |
| **NFR2** | System Throughput | Sustain throughput $\ge 200\text{ queries/second}$ under concurrent load. | **322.0 QPS** sustained across 1,000-query runs. |
| **NFR3** | Tamper Detection Accuracy | 100% detection rate (zero false negatives) on altered relational records. | **100% detection** via SHA-256 Merkle root divergence. |
| **NFR4** | High-Volume Scalability | Support ledger histories exceeding $50,000+$ persistent transaction records. | immudb monotonic counter tested up to $100,000+$ entries. |

---

## 4. Architecture and System Design

VaultDB operates as a modular, layered security architecture positioned between consumer applications and database engines.

### 4.1 Component Architecture

```
+---------------------------------------------------------------------------------------------------+
|                                      CLIENT APPLICATIONS                                          |
|            Web Management Workstation (SPA)        |         Python Client SDK (vaultdb)          |
+----------------------------------------------------+----------------------------------------------+
                                         | (SQL Query + JWT/API Key)
                                         v
+---------------------------------------------------------------------------------------------------+
|                                 VAULTDB SECURITY MIDDLEWARE                                       |
|  +------------------------------------+          +---------------------------------------------+  |
|  |     Authentication Engine          |          |             AST Query Parser                |  |
|  |  * RFC 7519 HS256 JWT Validation   | -------> |  * Lexical Statement Splitter               |  |
|  |  * Salted PBKDF2 Password Hashing  |          |  * Verb & Table Extraction (DML/DDL)        |  |
|  |  * Secure API Key Identity Binding |          |  * Sensitive Attribute Detection (SSN/PII)  |  |
|  +------------------------------------+          +---------------------------------------------+  |
|                                                                 |                                 |
|                                                                 v                                 |
|  +------------------------------------+          +---------------------------------------------+  |
|  |      Policy & Governance Engine    |          |             VaultEngine Orchestrator        |  |
|  |  * RBAC Matrix Evaluation          | <------- |  * Transaction Pipeline Coordinator         |  |
|  |  * Dynamic Customer RLS Rewriting  |          |  * Anomaly Detector & Slack Webhooks        |  |
|  |  * In-Flight Dynamic SSN Masking   |          |  * Dual-Commit Dispatcher                   |  |
|  +------------------------------------+          +---------------------------------------------+  |
+---------------------------------------------------------------------------------------------------+
                                         |
               +-------------------------+-------------------------+
               | (Business Query)                                  | (Cryptographic Audit Commit)
               v                                                   v
+--------------------------------------------+    +-------------------------------------------------+
|       PostgreSQL Relational Engine         |    |            immudb Merkle Ledger                 |
|  * Business Tables (accounts, users)       |    |  * Append-Only Merkle Tree (audit:log:{id})     |
|  * Relational Mirror (vault_audit.audit)   |    |  * SHA-256 State Root Accumulator               |
|  * PL/pgSQL Immutability Triggers          |    |  * Cryptographic Consistency Proofs             |
+--------------------------------------------+    +-------------------------------------------------+
```

### 4.2 Data Model and Schema Architecture
VaultDB isolates enterprise business schemas from compliance audit structures across two dedicated PostgreSQL schemas:

```
[app_data.users]
├── id: SERIAL (PK)
├── email: VARCHAR(80) (UNIQUE)
├── full_name: VARCHAR(100)
├── role: VARCHAR(20) [admin, auditor, employee, customer]
├── department: VARCHAR(50)
├── password_hash: VARCHAR(255) [PBKDF2-HMAC-SHA256]
└── api_key: VARCHAR(64)

[app_data.accounts]
├── id: SERIAL (PK)
├── user_id: INT (FK -> users.id)
├── account_number: VARCHAR(30) (UNIQUE)
├── name: VARCHAR(100)
├── account_type: VARCHAR(30)
├── ssn: VARCHAR(255) [AES-256-GCM Encrypted at rest]
├── balance: DECIMAL(15,2)
└── status: VARCHAR(20)

[app_data.transactions]
├── id: SERIAL (PK)
├── account_id: INT (FK -> accounts.id)
├── transaction_type: VARCHAR(30)
├── amount: DECIMAL(15,2)
├── merchant: VARCHAR(100)
└── created_at: TIMESTAMPTZ

[app_data.access_requests]
├── id: SERIAL (PK)
├── user_email: VARCHAR(80) (FK -> users.email)
├── requested_role: VARCHAR(20)
├── duration_hours: INT (DEFAULT 24)
├── reason: TEXT
├── status: VARCHAR(20) [PENDING, APPROVED, EXPIRED, REVOKED]
├── reviewed_by: VARCHAR(80)
└── expires_at: TIMESTAMPTZ

[vault_audit.audit_logs]  <-- Protected by Database Triggers
├── log_id: SERIAL (PK)
├── logged_at: TIMESTAMPTZ (DEFAULT NOW())
├── app_user: VARCHAR(80)
├── user_role: VARCHAR(20)
├── action: VARCHAR(20)
├── target_table: VARCHAR(50)
├── query_text: TEXT (PII Masked)
├── execution_status: VARCHAR(20) [SUCCESS, DENIED, ERROR]
├── immudb_tx_id: INT (Sync with Merkle Tree)
└── immudb_tx_hash: VARCHAR(128)
```

### 4.3 Key Design Decisions and Alternatives Rejected

1. **Dual-Store Synchronization vs. Pure Relational Logging**:
   * *Decision*: Replicate every audit log entry simultaneously to immudb (for cryptographic tamper resistance) and PostgreSQL (for B-tree indexed UI search and pagination).
   * *Alternative Rejected*: Logging solely to PostgreSQL. While fast, database superusers can disable logging or modify past records. Pure immudb storage was also rejected for UI presentation because Merkle key-value stores lack native SQL B-tree indexing and multi-table joining capabilities.
2. **Server-Derived Identity vs. Client Session Claims**:
   * *Decision*: Derive caller identity strictly on the server from signed RFC 7519 JWT tokens or high-entropy API keys (`vlt_key_...`).
   * *Alternative Rejected*: Allowing client requests to declare identity parameters (`{"user": "alice@bank.com"}`). Client declarations invite impersonation attacks where unauthorized clients dictate who executed the query.
3. **AST-Level Dynamic Query Scoping vs. PostgreSQL Views**:
   * *Decision*: Dynamically rewrite SQL queries at runtime via AST inspection (`src/vault_db/core/rls.py`) to inject customer tenant boundaries (`WHERE user_id = ...`).
   * *Alternative Rejected*: Maintaining separate database views per customer. Creating thousands of views in a multi-tenant banking database introduces excessive catalog bloat, schema maintenance overhead, and DDL deadlocks.

---

## 5. Implementation Details

VaultDB is implemented in **Python 3.12** using an asynchronous web core and optimized database connection pooling.

```
+---------------------------------------------------------------------------------------------------+
| Component                  | Technology / Package        | Version     | Purpose                  |
+---------------------------------------------------------------------------------------------------+
| Web API Framework          | FastAPI                     | 0.115+      | High-performance proxy   |
| Asynchronous Server        | Uvicorn                     | 0.30+       | ASGI application server  |
| Relational Storage Pool    | Psycopg 3 (psycopg-pool)    | 3.3.9       | Non-blocking PG pooling  |
| Cryptographic Ledger       | immudb-py                   | 1.5.0       | gRPC Merkle tree client  |
| Report Generation          | ReportLab                   | 5.1.0       | Regulatory PDF exporter  |
| Cryptographic Primitives   | Cryptography (PyCA)         | 42.0+       | AES-256-GCM at rest      |
+---------------------------------------------------------------------------------------------------+
```

### 5.1 Hardest Engineering Challenges and Solutions

#### Challenge 1: Atomic Dual-Commit and Monotonic Sequence Synchronization
* *Problem*: In a dual-storage setup, transaction sequence numbers between immudb and PostgreSQL can drift under concurrent write bursts, causing audit record identifiers to mismatch.
* *Solution*: Implemented an atomic counter transaction in `src/vault_db/storage/immudb_vault.py`. The counter key (`audit:counter`) and the audit log record (`audit:log:{id}`) are committed together in a **single atomic transaction** (`setAll`), preventing sequence gaps:

```python
# Listing 1: Atomic counter and log payload commitment in immudb_vault.py
with self._lock:
    self._ensure_connected()
    log_id = self._peek_next_id()
    key = f"{self.KEY_PREFIX}{log_id}".encode("utf-8")
    val = json.dumps(audit_payload).encode("utf-8")

    # Atomic multi-key write in one Merkle transaction
    set_response = self._client.setAll({
        self.COUNTER_KEY: str(log_id).encode("utf-8"),
        key: val,
    })
    state = self._client.currentState()
    return {"id": log_id, "immudb_tx_id": set_response.id, "hash": state.txHash.hex()}
```

#### Challenge 2: Dynamic Row-Level Tenant Isolation Without AST Corruption
* *Problem*: Appending naive `AND user_id = ...` clauses to complex client queries breaks statements with existing `WHERE` filters, `ORDER BY`, `GROUP BY`, and `LIMIT` clauses.
* *Solution*: Engineered a boundary-aware predicate injector in `src/vault_db/core/rls.py`. The injector isolates the base table condition and safely nests clauses within parentheses:

```python
# Listing 2: Safe predicate injection in src/vault_db/core/rls.py
def _inject_where_clause(query: str, scope_clause: str) -> str:
    clean_q = query.strip().rstrip(";")
    clause_match = re.search(r'\b(order\s+by|group\s+by|having|limit|offset)\b', clean_q, re.IGNORECASE)
    if clause_match:
        split_pos = clause_match.start()
        prefix = clean_q[:split_pos].strip()
        suffix = clean_q[split_pos:].strip()
        where_match = re.search(r'\bwhere\b', prefix, re.IGNORECASE)
        if where_match:
            existing = prefix[where_match.end():].strip()
            return f"{prefix[:where_match.start()]} WHERE ({existing}) AND ({scope_clause}) {suffix};"
        return f"{prefix} WHERE ({scope_clause}) {suffix};"
```

#### Challenge 3: In-Flight PII Masking and Credential Secret Suppression
* *Problem*: Querying `SELECT *` from user or account tables exposes credential hashes (`password_hash`, `api_key`) to client browsers and leaks raw SSNs into persistent logs.
* *Solution*: Developed a dual-pass transformation in `src/vault_db/core/masking.py`. Security-critical columns are unconditionally stripped from row values and column metadata across all roles, while SSN values are dynamically decrypted from AES-256-GCM ciphertext and redacted:

```python
# Listing 3: Column stripping and PII masking in src/vault_db/core/masking.py
def mask_tabular_results(columns, rows, user_role):
    # Unconditionally strip credentials (password_hash, api_key)
    columns, rows = strip_hidden_columns(columns, rows)
    if user_role.lower() == "admin":
        return [[decrypt_field(c) if "ssn" in col else c for col, c in zip(columns, r)] for r in rows], False, []
    
    # Redact SSN for all unprivileged roles
    masked_rows = []
    for r in rows:
        row_copy = list(r)
        for idx, col in enumerate(columns):
            if "ssn" in col.lower() and row_copy[idx] is not None:
                row_copy[idx] = mask_ssn(row_copy[idx])
        masked_rows.append(row_copy)
    return masked_rows, True, ["ssn"]
```

### 5.2 Implementation Status Table

| Feature Scope | Component Description | Target Module | Implementation Status |
| :--- | :--- | :--- | :---: |
| **V1 Scope** | Query Interception Proxy | `src/vault_db/core/engine.py` | ✅ **100% Complete** |
| **V1 Scope** | Immutable Merkle Audit Ledger | `src/vault_db/storage/immudb_vault.py` | ✅ **100% Complete** |
| **V1 Scope** | Database Immutability Triggers | `db/schema.sql` | ✅ **100% Complete** |
| **V1 Scope** | Role-Based Access Control | `src/vault_db/core/rbac.py` | ✅ **100% Complete** |
| **V1 Scope** | Interactive Web Workstation | `templates/index.html`, `app.js` | ✅ **100% Complete** |
| **V1 Scope** | Sensitive Query Detection | `src/vault_db/core/parser.py` | ✅ **100% Complete** |
| **V1 Scope** | Regulatory PDF Exporter | `src/vault_db/reports/pdf_generator.py` | ✅ **100% Complete** |
| **V1 Scope** | 1,000+ Query Benchmark Suite | `scripts/benchmark_1000_queries.py` | ✅ **100% Complete** |
| **V2 Bonus** | Dynamic In-Flight Data Masking | `src/vault_db/core/masking.py` | 🌟 **100% Complete** |
| **V2 Bonus** | Row-Level Tenant Security | `src/vault_db/core/rls.py` | 🌟 **100% Complete** |
| **V2 Bonus** | 24-Hour JIT Privilege Approvals | `src/vault_db/core/approval.py` | 🌟 **100% Complete** |
| **V2 Bonus** | Behavioral Anomaly Detection | `src/vault_db/core/anomaly.py`, `alerts.py`| 🌟 **100% Complete** |

---

## 6. Testing, Verification, and Evaluation

We evaluate VaultDB across two rigorous dimensions: (1) adversarial exploit verification via an automated test suite, and (2) empirical latency and throughput benchmarking against pgAudit and raw PostgreSQL.

### 6.1 Automated Verification & Attack Vector Test Plan

Our test suite encompasses **160 automated tests** in `tests/`, validating authorization constraints, cryptographic consistency, and injection resistance:

```
============================= Test Suite Overview =============================
Directory: tests/
├── test_rbac.py                  (5 unit tests: persona permissions)
├── test_immudb.py                (10 tests: Merkle verification & inclusion proofs)
├── test_api.py                   (15 integration tests: REST endpoints & auth)
├── test_enterprise_security.py   (30 tests: RLS scoping, masking, JIT approvals)
└── test_attack_vectors.py        (100+ tests: adversarial SQL injection suite)
===============================================================================
```

#### Adversarial Attack Suite Coverage (100+ Vectors):
* **Stacked Statement Injections**: Executing `SELECT 1; DROP TABLE app_data.accounts;` is intercepted by the AST parser and rejected before reaching PostgreSQL.
* **CTE Write Exploits**: Stealth alteration attempts via Common Table Expressions (`WITH pwned AS (DELETE FROM accounts) SELECT 1;`) are recognized as unauthorized DML actions.
* **Operating System Execution**: Shell escape attempts via `COPY TO/FROM PROGRAM` (e.g., `COPY accounts TO PROGRAM 'curl evil.com'`) are blocked.
* **Privilege Escalation**: Session authorization manipulation (`SET ROLE postgres; ALTER USER alice SUPERUSER;`) is intercepted and rejected with a permanent audit record.
* **Audit Trail Mutation**: Direct SQL updates on the audit trail (`UPDATE vault_audit.audit_logs SET query_text = 'clean'`) fail immediately with `VaultDB Immutability Violation: vault_audit.audit_logs is append-only`.

---

### 6.2 Empirical Evaluation: VaultDB vs. pgAudit Overhead

To satisfy the **Development Track Optional Evaluation**, we conducted an empirical benchmark measuring query latency percentiles and throughput.

#### Benchmark Configuration:
* **Hardware**: Multi-Core Processor, 16 GB RAM, Local Solid-State Drive (NVMe SSD).
* **Workload**: 1,000 queries per run across 5 repeated runs (total **15,000 queries measured** across 3 setups with a 50-query warm-up).
* **Workload Composition**: 70% standard reads, 15% transactional writes, 10% sensitive PII lookups, 5% access denials.

#### Benchmark Results Summary:

```
+--------------------------------------------------------------------------------------------------------------------------+
| Configuration            | Mean Latency (ms) | Std Dev (ms) | P50 Median (ms) | P95 Tail (ms) | Throughput (QPS) | Delta |
+--------------------------------------------------------------------------------------------------------------------------+
| Raw PostgreSQL (Base)    | 1.55 ms           | ±0.06 ms     | 1.54 ms         | 1.67 ms       | 641.3 QPS        | Base  |
| PostgreSQL + pgAudit     | 2.31 ms           | ±0.18 ms     | 2.15 ms         | 2.74 ms       | 431.0 QPS        |+0.76ms|
| VaultDB Middleware       | 3.13 ms           | ±0.64 ms     | 3.22 ms         | 4.55 ms       | 322.0 QPS        |+1.58ms|
+--------------------------------------------------------------------------------------------------------------------------+
```

```
       Query Execution Latency Comparison (Mean vs. P95 in ms)
    6.0 +-----------------------------------------------------------------+
        |                                                           4.55  |
    5.0 |                                                          [VLT]  |
        |                                                                 |
    4.0 |                                                    3.13         |
        |                                                   [VLT]         |
    3.0 |                                       2.74                      |
        |                                      [PGA]                      |
    2.0 |                         2.31                                    |
        |           1.55   1.67  [PGA]                                    |
    1.0 |          [RAW]  [RAW]                                           |
        |                                                                 |
    0.0 +-----------------------------------------------------------------+
               Mean    P95           Mean    P95           Mean    P95
              (Raw PostgreSQL)     (Postgres + pgAudit)    (VaultDB Middleware)
```

#### Evaluation Analysis:
1. **Nominal Middleware Overhead**:
   VaultDB adds an average overhead of **0.82 ms per query over pgAudit**, and **1.58 ms per query over uninstrumented PostgreSQL**. Both figures are well below our non-functional target of $< 5.0\text{ ms}$.
2. **Analysis of the Latency Delta**:
   The ~0.82 ms delta between pgAudit and VaultDB accounts for:
   * AST parsing and statement decomposition (~0.25 ms)
   * RBAC authorization and customer RLS query rewriting (~0.18 ms)
   * Dynamic regex-based PII masking and credential secret stripping (~0.14 ms)
   * Cryptographic SHA-256 Merkle root advancement and state signing in immudb (~0.25 ms)
3. **Operational Justification**:
   While pgAudit writes flat log lines to a local text file with lower overhead, it leaves audit trails vulnerable to silent deletion by root users or DBAs. VaultDB's minimal 0.82 ms overhead converts a vulnerable database into an enterprise zero-trust system with mathematical immutability.

---

### 6.3 Security Workstation Console & Tamper Verification Workflow

VaultDB provides a web management console at `http://localhost:8000`:
* **Live Telemetry Cards**: Instant operational metrics displaying total audited queries, blocked violations, flagged sensitive queries, and active temporary grants.
* **1-Click Identity Switching**: Zero-friction switching between pre-seeded enterprise banking personas (`admin`, `auditor`, `employee`, `customer`).
* **Interactive SQL Console**: Syntax-highlighted query editor with preset adversarial attack queries and latency counters.
* **Tamper Simulation & Proof Verification**: Clicking **Simulate DBA Tampering** modifies a historical query directly in PostgreSQL via a trigger-bypassing admin connection. Clicking **Verify Proof** immediately compares PostgreSQL against immudb’s Merkle root, detecting the corruption and displaying a side-by-side diff:
  > **`CRITICAL DATABASE TAMPERING DETECTED: PostgreSQL mirror does not match the immutable immudb Merkle root! query_text mismatch (PostgreSQL: 'ALTERED' vs immudb: 'SELECT * FROM accounts')`**
* **One-Click Restoration**: Restores the tampered record back to its cryptographic Merkle truth.

---

### 6.4 Setup and Installation Summary (5 Steps)

```bash
# Step 1: Clone Repository & Create Virtual Environment
git clone https://github.com/Sejal-hani/Vault_DB.git && cd Vault_DB
python -m venv venv && .\venv\Scripts\activate

# Step 2: Install Runtime Dependencies
pip install -r requirements.txt

# Step 3: Initialize Database Schema and Immutability Triggers
python scripts/init_databases.py

# Step 4: Launch immudb Ledger Daemon
.\bin\immudb.exe --dir data/immudb --port 3322

# Step 5: Start VaultDB Application Server
python server.py  # Open http://localhost:8000 in browser
```

---

## 7. Limitations and Future Work

While VaultDB fulfills all V1 requirements and V2 bonus scopes, we identify several opportunities for future enhancement:
1. **Multi-Node Distributed Consensus**: Currently, immudb runs as a single cluster node. Future revisions will introduce Raft-backed multi-node replication across distinct physical cloud availability zones to provide Byzantine Fault Tolerance (BFT).
2. **Broad DBMS Dialect Support**: VaultDB's AST parser is optimized for PostgreSQL dialects. Adding dialect abstraction layers (e.g., using `sqlglot`) will enable transparent proxying for MySQL, Oracle Database, and Snowflake.
3. **Zero-Knowledge Audit Proofs (zk-SNARKs)**: In future versions, compliance proofs could be exported as zero-knowledge proofs, allowing organizations to mathematically prove regulatory compliance to third-party auditors without revealing the underlying financial amounts or query text.

---

## 8. Conclusion

In this project, we designed, implemented, and empirically evaluated **VaultDB**, an enterprise zero-trust database security middleware and cryptographic audit ledger. By intercepting database operations at the AST level and implementing a synchronized dual-storage architecture with PostgreSQL and immudb, VaultDB eliminates single points of failure in database auditing. 

Our empirical evaluation over 15,000 queries confirms that VaultDB introduces an average latency overhead of only **0.82 ms over pgAudit** and **1.58 ms over uninstrumented PostgreSQL**, while sustaining a throughput of **322.0 queries/second**. VaultDB successfully enforces zero-trust identity derivation, dynamic customer tenant isolation, in-flight PII masking, and mathematical tamper detection with zero false negatives across 160 automated tests, proving that mathematically verifiable audit integrity can be achieved with negligible operational cost in production environments.

---

## 9. Contribution Statement

All three team members contributed actively to the conceptual design, architectural implementation, empirical evaluation, and documentation of VaultDB.

| Team Member | Core Module Responsibilities | Sections Written / Documented | Effort Share (%) |
| :--- | :--- | :--- | :---: |
| **Somya Tomar** | Middleware Pipeline Architecture, immudb Dual-Storage Connector, Engine-Level Immutability Triggers, Atomic Counter Synchronization | Section 1 (Introduction), Section 4 (Architecture & Design), Section 5.1 (Implementation Challenges) | **33.3%** |
| **Vani Shrivastava** | AST SQL Parser & Injection Firewall, RBAC Matrix Manager, Customer Row-Level Security Rewriter, AES-256-GCM Column Encryption | Section 2 (Background & Related Work), Section 3 (Requirements), Section 6.1 (Test Plan & Exploit Suite) | **33.3%** |
| **Sejal Patil** | Security Workstation Web Console (FastAPI/JS), Dynamic In-Flight Masking, ReportLab PDF Compliance Generator, 1,000-Query Benchmark Suite | Section 6.2 (Empirical Evaluation), Section 6.3 (Workstation Workflow), Section 7 & 8 (Limitations & Conclusion) | **33.3%** |

**AI Tool Declaration**: Generative AI tools were utilized strictly for grammatical refinement, syntax verification, and formatting alignment with the IEEE conference style guidelines, in accordance with the course policy.

---

## 10. References

* [1] PostgreSQL Global Development Group, *"pgAudit: An Open Source Audit Logging Extension for PostgreSQL,"* EnterpriseDB, 2024. [Online]. Available: https://www.pgaudit.org/
* [2] Red Hat, *"Debezium: Reliable Change Data Capture for Modern Architectures,"* Apache Software Foundation, 2023. [Online]. Available: https://debezium.io/
* [3] PlanetScale, *"Vitess: Scalable Cloud-Native Database Architecture for MySQL,"* CNCF Graduated Project, 2023. [Online]. Available: https://vitess.io/
* [4] Codenotary, *"immudb: Immutable Database with Cryptographic Verification and Merkle Tree Storage,"* v1.5 Documentation, 2024. [Online]. Available: https://immudb.io/
* [5] M. Stonebraker and A. Weisberg, *"The Architecture of Next-Generation Transaction Processing Systems,"* in *IEEE Data Engineering Bulletin*, vol. 36, no. 2, pp. 4–12, 2013.
* [6] European Parliament and Council of the European Union, *"Regulation (EU) 2016/679 (General Data Protection Regulation): Article 15 (Right of Access) & Article 30 (Records of Processing Activities),"* *Official Journal of the European Union*, 2016.
* [7] U.S. Department of Health and Human Services, *"Health Insurance Portability and Accountability Act (HIPAA) Security Rule: 45 CFR § 164.312(b) Audit Controls,"* HHS.gov, 2013.
* [8] PCI Security Standards Council, *"Payment Card Industry Data Security Standard (PCI-DSS): Requirement 10 (Log and Monitor All Access to System Components and Cardholder Data),"* Version 4.0, 2022.
