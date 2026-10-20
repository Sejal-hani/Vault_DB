# VaultDB Setup & Installation Guide

This guide provides step-by-step instructions to install, configure, initialize, and test **VaultDB** on a local development machine or production server.

---

## 1. System Prerequisites

Before beginning, ensure the following software is installed on your machine:

| Component | Minimum Version | Notes |
| :--- | :--- | :--- |
| **Python** | 3.10+ (Recommended: 3.12) | Core middleware runtime |
| **PostgreSQL** | 14+ (Recommended: 16) | Underlying relational database |
| **immudb** | 1.5+ | Append-only cryptographic Merkle tree ledger |
| **Git** | 2.30+ | Source code version control |

---

## 2. Environment Setup

### Step 2.1: Clone Repository
```bash
git clone <repo-url> Vault_DB
cd Vault_DB
```

### Step 2.2: Create Python Virtual Environment
```bash
# Windows
python -m venv venv
.\venv\Scripts\activate

# Linux / macOS
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

Create or verify the `.env` file in the root directory:
```ini
# PostgreSQL Relational Business Store
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=5432
POSTGRES_DB=vaultdb
POSTGRES_USER=vault_user
POSTGRES_PASSWORD=vault123

# PostgreSQL Admin (for initial DDL, schema, and trigger setup)
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
```

---

## 4. Database Initialization

Run the automated database setup and seeding script. This executes [schema.sql](schema.sql), establishes database triggers for immutability, encrypts sensitive data at rest using AES-256-GCM, and seeds demo personas:

```bash
python scripts/init_databases.py
```

---

## 5. Starting Services

### 5.1 Start immudb Ledger
In a dedicated terminal window:
```powershell
# Windows
.\bin\immudb.exe --dir data/immudb --pgsql-server=true --pgsql-server-port=5433 --port=3322

# Linux / macOS
./bin/immudb --dir data/immudb --pgsql-server=true --pgsql-server-port=5433 --port=3322
```

### 5.2 Start the VaultDB Web Console & API Server
In a second terminal window:
```bash
python server.py
```

The interactive security console will be live at:
- **Web Dashboard**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive Swagger Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **System Health Check**: [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)

---

## 6. Demo Persona Credentials

Use the 1-click persona switcher on the dashboard or log in with these pre-seeded accounts:

| Persona | Email | Password | Role | Permissions |
| :--- | :--- | :--- | :--- | :--- |
| **Admin** | `admin@bank.com` | `AdminPass123!` | `admin` | Full CRUD + DDL on all tables |
| **Auditor** | `compliance.lead@bank.com` | `AuditorPass123!` | `auditor` | Read-only across all tables + unmasked audit |
| **Writer** | `sarah.writer@bank.com` | `WriterPass123!` | `writer` | Read & write on accounts, transactions, reports |
| **Reader** | `bob.reader@bank.com` | `ReaderPass123!` | `reader` | Read-only on accounts, transactions, reports |
| **Employee** | `john@bank.com` | `EmployeePass123!` | `employee` | Read accounts, create/update transactions |
| **Customer** | `alice@bank.com` | `CustomerPass123!` | `customer` | RLS isolated to personal accounts & transactions |

---

## 7. Verification & Testing

### 7.1 Run Full Test Suite
Executes all unit, security, RBAC, RLS, cryptographic verification, and API integration tests:
```bash
pytest -v
```

### 7.2 Run High-Volume 1,000+ Query Benchmark
Tests throughput, concurrency, RBAC enforcement, and Merkle tree state commitments across 1,000 queries:
```bash
python scripts/benchmark_1000_queries.py
```

### 7.3 Verify Cryptographic Proofs
Audits the latest transactions in immudb and verifies Merkle inclusion proofs:
```bash
python scripts/verify_integrity.py
```
