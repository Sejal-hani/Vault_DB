"""
High-Scale Dataset Generator for VaultDB
Generates up to 1,000,000+ realistic banking and transaction records directly in PostgreSQL
using high-performance bulk operations (generate_series).
Compatible with Kaggle PaySim / Financial Fraud dataset schemas.
"""

import sys
import time
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

import psycopg
from config.settings import settings


def generate_scale_dataset(target_rows: int = 100000):
    print("=" * 75)
    print(f" VaultDB High-Scale Bulk Data Generator: {target_rows:,} Transactions")
    print("=" * 75)

    print(f"[*] Connecting to PostgreSQL at {settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}...")
    t0 = time.perf_counter()

    sql = f"""
    -- Ensure indexes exist
    CREATE INDEX IF NOT EXISTS idx_transactions_account_id ON app_data.transactions(account_id);
    CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON app_data.transactions(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_transactions_status ON app_data.transactions(status);

    -- Bulk generate realistic financial transactions using generate_series
    INSERT INTO app_data.transactions (account_id, transaction_type, amount, merchant, status, created_at)
    SELECT
        (1 + floor(random() * 35))::int AS account_id,
        (ARRAY['WIRE', 'TRANSFER', 'DEPOSIT', 'PURCHASE', 'PAYROLL', 'SETTLEMENT'])[floor(random() * 6 + 1)] AS transaction_type,
        round((random() * 50000 + 10)::numeric, 2) AS amount,
        (ARRAY['JPMorgan Treasury', 'SWIFT Settlement', 'Federal Reserve Wire', 'Stripe Payments', 'Amazon AWS EMEA', 'Apex Clearing', 'Deloitte Settlement'])[floor(random() * 7 + 1)] AS merchant,
        (ARRAY['completed', 'completed', 'completed', 'pending', 'flagged'])[floor(random() * 5 + 1)] AS status,
        NOW() - (random() * interval '90 days') AS created_at
    FROM generate_series(1, {target_rows});
    """

    with psycopg.connect(settings.postgres_admin_conninfo, autocommit=True) as conn:
        with conn.cursor() as cur:
            print(f"[*] Executing bulk generation of {target_rows:,} rows...")
            cur.execute(sql)
            
            cur.execute("SELECT COUNT(*) FROM app_data.transactions;")
            total_tx = cur.fetchone()[0]

            cur.execute("SELECT COUNT(*) FROM app_data.accounts;")
            total_acc = cur.fetchone()[0]

    elapsed = time.perf_counter() - t0
    rate = target_rows / elapsed

    print(f"[+] Successfully generated {target_rows:,} transactions in {elapsed:.2f} seconds ({rate:,.0f} rows/sec).")
    print(f"[+] Total transactions currently in app_data.transactions: {total_tx:,}")
    print(f"[+] Total accounts in app_data.accounts:                 {total_acc:,}")
    print("=" * 75)


if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 100000
    generate_scale_dataset(count)
