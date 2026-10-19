# VaultDB: System Setup & Deployment Guide

> **VaultDB**: Cryptographic Compliance & Audit Middleware  
> Certified Immutable Audit Logging, Fine-Grained RBAC, Row-Level Security, Dynamic Masking, and Cryptographic Tamper Verification (GDPR / HIPAA / PCI-DSS)

---

## 1. System Prerequisites

Before running VaultDB, ensure the following tools are installed on your operating system:

| Component | Minimum Version | Purpose |
| :--- | :--- | :--- |
| **Python** | 3.11+ / 3.12+ | Core runtime for FastAPI, query middleware, crypto adapters |
| **PostgreSQL** | 16+ | Relational storage for business datasets (`app_data`) and mirror audit logs (`vault_audit`) |
| **immudb** | 1.9.5+ | Append-only cryptographic Merkle tree ledger (pre-compiled binary included in `bin/`) |
| **Docker & Compose** | Optional | For one-command turnkey containerized deployment |

---

## 2. Quickstart Deployment

### Option A: Turnkey Docker Compose Deployment

If Docker is installed:

```bash
docker compose up --build
```

This single command:
1. Spawns PostgreSQL 16 on port `5432`.
2. Spawns immudb on ports `3322` and `5433`.
3. Runs database initialization (`scripts/init_databases.py`) and auth/trigger migrations (`scripts/apply_auth_and_triggers.py`).
4. Launches the VaultDB web application on `http://localhost:8000`.

---

### Option B: Local Setup (Windows / Linux / macOS)

#### Step 1: Create Virtual Environment & Install Dependencies

```powershell
# Create virtual environment
python -m venv venv

# Activate virtual environment (Windows PowerShell)
.\venv\Scripts\Activate.ps1

# (On Linux / macOS: source venv/bin/activate)

# Install requirements
pip install -r requirements.txt
```

#### Step 2: Initialize PostgreSQL & Apply Migrations

Ensure PostgreSQL is running locally on port 5432:

```powershell
# 1. Initialize schemas, tables, and roles
python scripts/init_databases.py

# 2. Apply auth credentials, hashed passwords, API keys, and immutability triggers
python scripts/apply_auth_and_triggers.py
```

#### Step 3: Launch immudb Service

In a separate terminal or background session:

```powershell
# Windows
.\bin\immudb.exe --dir data/immudb --pgsql-server=true --pgsql-server-port=5433 --port=3322

# Linux / macOS
chmod +x ./bin/immudb
./bin/immudb --dir data/immudb --pgsql-server=true --pgsql-server-port=5433 --port=3322
```

#### Step 4: Launch VaultDB Web Server

```powershell
python server.py
```

Console Output:
```
=================================================================
 VaultDB Dashboard running at http://localhost:8000
 Interactive Swagger API Docs at http://localhost:8000/docs
=================================================================
```

---

## 3. Demo Persona Credentials

Use the one-click persona bar in the web UI, or use the pre-seeded credentials below:

| Role | Email | Password | API Key | Department |
| :--- | :--- | :--- | :--- | :--- |
| **Admin** | `admin@bank.com` | `AdminPass123!` | `vlt_key_admin_9a8b7c6d5e4f3a2b` | SecOps |
| **Auditor** | `compliance.lead@bank.com` | `AuditorPass123!` | `vlt_key_auditor_5d6e7f8a9b0c1d2e` | Regulatory Compliance |
| **Employee** | `john@bank.com` | `EmployeePass123!` | `vlt_key_employee_1a2b3c4d5e6f7a8b` | Commercial Lending |
| **Customer** | `alice@bank.com` | `CustomerPass123!` | `vlt_key_customer_4d5e6f7a8b9c0d1e` | Private Banking |

---

## 4. Test Suite Execution

Run the complete 135-test suite covering authentication lifecycles, attack vector prevention, PostgreSQL triggers, masking, RLS, and immudb cryptographic proofs:

```powershell
.\venv\Scripts\pytest.exe -v
```

Expected result:
```
======================= 135 passed, 1 warning in 5.19s =======================
```

---

## 5. Security & Verification CLI Tools

### Cryptographic Merkle Root Audit
```powershell
# Audit recent transactions
python scripts/verify_integrity.py --limit 10

# Audit specific log ID
python scripts/verify_integrity.py --log-id 1
```

### High-Throughput Adversarial Attack Benchmark
```powershell
python scripts/test_10000_adversarial_queries.py
```
