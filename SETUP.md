# VaultDB Setup & Installation Guide

This guide provides simple, step-by-step instructions to install, configure, initialize, and run **VaultDB** on any machine (macOS, Linux, or Windows).

---

## 1-Command Universal Quickstart

VaultDB includes an automated launcher that auto-detects your OS, verifies Python, sets up configurations, and initializes the cryptographic ledger:

```bash
# Windows:
run.bat

# macOS / Linux:
chmod +x run.sh && ./run.sh

# Or direct Python (all operating systems):
python scripts/quickstart.py
```
Open **`http://localhost:8000`** in your browser.

---

## 1. Prerequisites

Before starting, make sure you have:
* **Python**: 3.10+ (Recommended: 3.12)
* **PostgreSQL**: 14+ (running locally on port 5432, optional for in-memory/native mode)
* **Cryptographic Ledger**:
  * **Option A (Zero-Dependency)**: Native Pure-Python Merkle Tree Ledger (RFC 6962) — **pre-installed, zero external binaries, runs on macOS, Linux, and Windows**.
  * **Option B (Enterprise Service)**: immudb daemon running on port 3322 (pre-bundled in `bin/` for Windows, or via Docker).
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

VaultDB includes a ready-to-use `.env.example`. Copy or create a `.env` file in the project root:

```ini
# Storage Backend: auto (try immudb, fallback to native pure-Python Merkle tree), merkle, or immudb
STORAGE_BACKEND=auto

# PostgreSQL Relational Store
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=5432
POSTGRES_DB=vaultdb
POSTGRES_USER=vault_user
POSTGRES_PASSWORD=vault123

# PostgreSQL Admin (for initial DDL and triggers)
POSTGRES_ADMIN_USER=postgres
POSTGRES_ADMIN_PASSWORD=postgres

# immudb Cryptographic Ledger (used if STORAGE_BACKEND=immudb or auto with daemon alive)
IMMUDB_HOST=127.0.0.1
IMMUDB_PORT=3322
IMMUDB_USER=immudb
IMMUDB_PASSWORD=immudb
IMMUDB_DATABASE=defaultdb

# Web Application
APP_HOST=0.0.0.0
APP_PORT=8000
DEBUG=False
```

---

## 4. Running the Complete System

### Option A: 1-Click Launch (Recommended)
```bash
python scripts/quickstart.py
```

### Option B: Step-by-Step Manual Launch
1. **Initialize Schemas & Seed Data**:
   ```bash
   python scripts/init_databases.py
   ```
2. **Start Services & Web Console**:
   ```bash
   python scripts/start_services.py
   ```
3. Open **`http://localhost:8000`** in your browser.
