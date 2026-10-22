# VaultDB Setup & Installation Guide

This guide provides simple, step-by-step instructions to install, configure, initialize, and run **VaultDB** on your machine.

---

## 1. Prerequisites

Before starting, make sure you have:
* **Python**: 3.10+ (Recommended: 3.12)
* **PostgreSQL**: 14+ (running locally on port 5432)
* **immudb**: Pre-bundled executable in `bin/` or downloaded from official releases
* **Git**: Installed and configured

---

## 2. Installation & Environment Setup

### Step 2.1: Clone Repository
```bash
git clone https://github.com/Sejal-hani/Vault_DB.git
cd Vault_DB
```

### Step 2.2: Create and Activate Virtual Environment
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# macOS / Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 2.3: Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 3. Configuration (.env)

Verify or create a `.env` file in the project root:

```ini
# PostgreSQL Relational Store
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=5432
POSTGRES_DB=vaultdb
POSTGRES_USER=vault_user
POSTGRES_PASSWORD=vault123

# PostgreSQL Admin (for initial DDL and triggers)
POSTGRES_ADMIN_USER=postgres
POSTGRES_ADMIN_PASSWORD=postgres

# immudb Cryptographic Ledger
IMMUDB_HOST=127.0.0.1
IMMUDB_PORT=3322
IMMUDB_USER=immudb
IMMUDB_PASSWORD=immudb
IMMUDB_DATABASE=defaultdb

# Security & Secrets
SECRET_KEY=vlt_sec_8f93e2b10a4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=60
```

---

## 4. Database Initialization

Run the automated setup script to create database schemas, configure PL/pgSQL immutability triggers, and seed demo personas and accounts:

```bash
python scripts/init_databases.py
```

---

## 5. Starting the Services

You need two services running: **immudb** and the **VaultDB Web Server**.

### Option A: Separate Terminals (Recommended for Development)

**Terminal 1 — Start immudb:**
```powershell
# Windows
.\bin\immudb.exe --dir data/immudb --pgsql-server=true --pgsql-server-port=5433 --port=3322

# macOS / Linux
./bin/immudb --dir data/immudb --pgsql-server=true --pgsql-server-port=5433 --port=3322
```

**Terminal 2 — Start VaultDB:**
```bash
python server.py
```

### Option B: All-In-One Launcher
```bash
python scripts/start_services.py
```

---

## 6. Accessing the Dashboard

Once started, open your web browser to:
* **Web Management Console**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
* **Interactive API Docs (Swagger)**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
* **Health Check**: [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)

### 1-Click User Persona Switcher
In the top navigation bar of the dashboard, you can switch between pre-seeded enterprise personas with a single click:
* **Admin** (`admin@bank.com`): Full administrative CRUD permissions and schema inspection.
* **Auditor** (`compliance.lead@bank.com`): Read-only audit access, Merkle proof verification, and certified PDF export.
* **Employee** (`john@bank.com`): Operational account access and transaction management with masked sensitive PII.
* **Customer** (`alice@bank.com`): Strictly isolated to personal records via Row-Level Security (RLS).

---

## 7. Testing & Verification

### Run Automated Test Suite
Execute the full suite of unit, security, RBAC, and cryptographic integrity tests:
```bash
pytest -v
```

### Run High-Volume 1,000+ Query Test
Verify database throughput, concurrency, and audit logging under load:
```bash
python scripts/benchmark_1000_queries.py
```

### Verify Cryptographic Integrity
Run the independent integrity verifier to cross-check PostgreSQL audit logs against immudb Merkle roots:
```bash
python scripts/verify_integrity.py
```
