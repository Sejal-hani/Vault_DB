# VaultDB High-Volume Benchmark & Architectural Evaluation

## 1. High-Volume Benchmark Summary (1,000 Queries)

This benchmark evaluates the performance, throughput, latency, and cryptographic consistency of the **VaultDB** middleware pipeline under high-volume enterprise banking traffic.
* **Script**: `scripts/benchmark_1000_queries.py`
* **Dataset & Workload**: 1,000 queries executing against `app_data.accounts`, `transactions`, and `users`.
* **Workload Composition**:
  - Authorized reads (SELECT on accounts and transactions under RBAC)
  - Authorized transactional writes (UPDATE on transactions)
  - Customer tenant-scoped queries (evaluated under Row-Level Security)
  - Prohibited queries (RBAC security violations: unprivileged UPDATE and INSERT attempts)
  - Sensitive attribute queries (accessing SSN and credentials)

### Measured Results (Live Test Run):
* **Total Queries Executed**: 1,000
* **Total Execution Time**: 50.87 seconds
* **Throughput**: **19.7 queries/second** (full dual-commit synchronous durability to PostgreSQL and immudb)
* **Median Latency (P50)**: **49.70 ms**
* **95th Percentile Latency (P95)**: **145.80 ms**
* **99th Percentile Latency (P99)**: **159.67 ms**
* **Workload Breakdown**:
  - **Authorized Queries (SUCCESS)**: 662
  - **Security Violations Intercepted (DENIED)**: 240
  - **Sensitive Queries Flagged**: 109
* **immudb Ledger Advancement**:
  - Starting Transaction Height: `#72`
  - Final Transaction Height: `#974`
  - Cryptographic Transactions Committed: **902**
  - Final Merkle Root Hash: `4bb320154fdcd86620185a745ab7548bd975c7341cb82252513ea365e4e61e1f`
* **Tamper Detection Accuracy**: **100%** (zero false negatives on cryptographic Merkle tree consistency checks)
* **Attack Rejection**: **100%** of unauthorized queries blocked with permanent audit logging.

---

## 2. Architectural Comparison: VaultDB vs. pgAudit

The course syllabus suggests evaluating VaultDB against standard database auditing tools like **pgAudit**:
> *"Optional evaluation to strengthen the report: Overhead of your audit middleware vs pgAudit."*

### Architectural Differences:

| Capability | PostgreSQL with pgAudit | VaultDB Security Middleware |
| :--- | :--- | :--- |
| **Architecture Layer** | Internal PostgreSQL executor C-hook (`ExecutorRun_hook`) | External Zero-Trust Security Proxy & Middleware |
| **Audit Log Destination** | Plaintext files (`syslog`, `csvlog`, `stderr`) | Synchronized Dual-Storage: PostgreSQL + immudb Merkle Tree |
| **Tamper Resistance** | ❌ **None** (Any DBA, root user, or compromised server can modify/delete files) | ✅ **Mathematically Immutable** (Append-only Merkle tree with SHA-256 state roots) |
| **Cryptographic Inclusion Proofs** | ❌ **None** | ✅ **Yes** (`verifiedGet` cryptographic proofs) |
| **Client Identity Spoofing Protection** | ❌ **None** (Trusts connection pool or session claims) | ✅ **Server-Derived Identity** (RFC 7519 JWT tokens & salted PBKDF2 hashes) |
| **In-Flight Dynamic PII Masking** | ❌ **None** (SSNs and secrets written in plaintext) | ✅ **Yes** (SSNs masked as `***-**-1234`; secrets stripped) |
| **Row-Level Security (Tenant Isolation)** | ❌ **Manual** (Requires manual application WHERE clauses) | ✅ **Automatic** (AST query rewriter injects customer boundaries) |
| **SQL Injection Firewall** | ❌ **None** (Logs query after it reaches executor) | ✅ **Pre-Execution AST Firewall** (Blocks stacked queries & unprivileged DDL) |
| **Compliance UI & Reports** | ❌ **None** (Raw log text only) | ✅ **Web Workstation & Certified PDF Exporter** |

### Trade-Off Analysis:
1. **pgAudit Operational Profile**: pgAudit is implemented in C directly within the PostgreSQL server process. It captures SQL statements at the executor hook level and flushes raw strings to syslog or disk. Because it avoids network proxy hops, parsing, or cryptographic hashes, its overhead is minimal (< 1 ms). However, **pgAudit logs are completely mutable and vulnerable**: any database administrator, privileged service account, or root user can delete or tamper with `/var/log/postgresql/*.log` without leaving any forensic trace.
2. **VaultDB Zero-Trust Value**: VaultDB operates as an inline security middleware proxy that parses the SQL AST, enforces RBAC, isolates customer tenants via dynamic RLS query rewriting, redacts sensitive PII in flight, and synchronizes transactions into an immutable immudb Merkle tree ledger. Every transaction receives a SHA-256 cryptographic proof, providing mathematical non-repudiation and automated tamper detection. This satisfies stringent regulatory mandates (GDPR Article 30, HIPAA §164.312, PCI-DSS Requirement 10.2) that pgAudit cannot address.
