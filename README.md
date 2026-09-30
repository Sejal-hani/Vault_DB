# VaultDB (v2.0)

> **Cryptographically Immutable Database Middleware with PostgreSQL & immudb**  
> Meets compliance standards (GDPR Art. 30, HIPAA §164.312) by answering:  
> *"Who accessed what data, what exact SQL query was run, when, and can you mathematically prove the audit trail was never tampered with?"*

---

## 🌟 Key Highlights & What's New in v2.0

1. **immudb Cryptographic Immutability**:
   - Zero-trust audit trails committed to **immudb** using append-only Merkle trees.
   - Cryptographic verification proofs (`verifiedSet` / `verifiedGet`) guaranteeing logs cannot be altered, deleted, or backdated—even by database administrators.
2. **Production Scalability**:
   - **PostgreSQL Connection Pooling (`psycopg_pool`)**: Eliminates connection latency under concurrent load.
   - **High-Performance Asynchronous API (`FastAPI` + `Uvicorn`)**: High-throughput REST API with interactive Swagger docs.
3. **Enterprise Project Structure**:
   - Clean layered architecture separating `core` (RBAC, SQL parser), `storage` (Postgres, immudb), and `api` (FastAPI routes, schemas).
4. **Interactive Dashboard**:
   - Live immudb ledger height and Merkle tree root hash indicator.
   - Interactive SQL query tester with RBAC feedback.
   - **"🛡️ Verify Proof"** button on each log record validating Merkle cryptographic proofs on the fly.
5. **CLI Verification Tool**:
   - `python scripts/verify_integrity.py` generates an audited tamper-proof report for compliance inspections.

---

## 📂 Project Directory Structure

```
Vault_DB/
├── bin/
│   └── immudb.exe                  # Standalone immudb server binary (Windows)
├── config/
│   ├── __init__.py
│   └── settings.py                 # Centralized 12-factor configuration
├── src/
│   └── vault_db/
│       ├── __init__.py
│       ├── core/
│       │   ├── rbac.py             # Role-Based Access Control matrix & policies
│       │   ├── parser.py           # SQL parsing, action extraction & sensitive column detector
│       │   └── engine.py           # VaultEngine middleware orchestrator
│       ├── storage/
│       │   ├── postgres.py         # PostgreSQL client with psycopg-pool
│       │   └── immudb_vault.py     # immudb client (verified writes & Merkle proofs)
│       └── api/
│           ├── models.py           # Pydantic schemas
│           ├── routes.py           # REST endpoints (/api/execute, /api/logs, /api/verify)
│           └── app.py              # FastAPI application
├── templates/
│   └── index.html                  # Upgraded Dashboard UI
├── scripts/
│   ├── init_databases.py           # PostgreSQL & immudb dual-database initialization
│   ├── start_services.py           # One-click launcher for immudb & FastAPI
│   ├── start_immudb.ps1            # PowerShell helper to run immudb standalone
│   └── verify_integrity.py         # CLI tool to cryptographically audit logs
├── tests/
│   ├── test_rbac.py                # RBAC unit tests
│   ├── test_immudb.py              # immudb verified operations & tamper proofs
│   └── test_api.py                 # FastAPI endpoint integration tests
├── .env.example                    # Sample environment variables
├── requirements.txt                # Project dependencies
├── ARCHITECTURE.md                 # Detailed architecture specification & viva Q&A
└── README.md                       # Documentation & Quickstart
```

---

## 🚀 Quickstart Guide

### 1. Requirements
* Python 3.12+
* PostgreSQL 16+ (Running on default port `5432`)
* immudb standalone binary (Pre-packaged in `bin/immudb.exe`)

### 2. Installation
```powershell
# 1. Activate virtual environment
.\venv\Scripts\Activate.ps1

# 2. Install dependencies
pip install -r requirements.txt
```

### 3. Initialize Databases (PostgreSQL + immudb)
```powershell
python scripts/init_databases.py
```

### 4. Start immudb & Web Dashboard
```powershell
# Launches immudb service and the FastAPI dashboard server
python scripts/start_services.py
```

* **Web Studio Console**: Open [http://localhost:8000](http://localhost:8000) in your browser.
* **Interactive API Docs (Swagger UI)**: Open [http://localhost:8000/docs](http://localhost:8000/docs).

---

## 🧪 Running Automated Tests

All tests verify RBAC rules, immudb cryptographic proofs, and FastAPI endpoints:
```powershell
pytest -v
```

---

## 🛡️ Verifying Cryptographic Proofs via CLI

Verify that audit records in the immudb ledger have never been modified:
```powershell
# Audit all recent logs
python scripts/verify_integrity.py

# Verify a specific audit log ID with full cryptographic details
python scripts/verify_integrity.py --log-id 1
```

---

## 💻 Python SDK Usage

```python
from vault_client import VaultClient

client = VaultClient()

# 1. Execute authorized query under customer identity
results = client.execute("SELECT * FROM app_data.accounts;", app_user="alice@bank.com")
print("Results:", results)

# 2. Retrieve recent audit logs from immudb
logs = client.get_audit_logs(limit=1)
print("Latest Log:", logs[0])

# 3. Cryptographically verify proof
proof = client.verify_audit_log(log_id=logs[0][0])
print("Merkle Proof Verified:", proof["verified"])

client.close()
```

---

## 📚 Architectural Viva Questions

See **[ARCHITECTURE.md](ARCHITECTURE.md)** for in-depth explanations on:
* Why PostgreSQL triggers/permissions are insufficient for compliance auditing.
* How immudb implements Merkle-tree cryptographic tamper evidence.
* Connection pooling and scalability design patterns.