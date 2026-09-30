"""
Kaggle Financial Dataset Importer for VaultDB
Streams and bulk-imports massive Kaggle datasets into VaultDB PostgreSQL tables.

Recommended Kaggle Datasets:
1. PaySim Synthetic Financial Dataset for Fraud Detection
   URL: https://www.kaggle.com/datasets/ealaxi/paysim1
   Rows: 6,362,620 transactions (500MB CSV)
   Columns: step, type, amount, nameOrig, oldbalanceOrg, newbalanceOrig, nameDest, oldbalanceDest, newbalanceDest, isFraud

2. Credit Card Fraud Detection
   URL: https://www.kaggle.com/datasets/mlg-ulb/creditcardfraud
   Rows: 284,807 transactions

Usage:
  python scripts/import_kaggle_dataset.py path/to/paysim.csv --limit 500000
"""

import sys
import csv
import time
import argparse
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

import psycopg
from config.settings import settings


def import_paysim_csv(csv_path: str, limit: int = 100000, batch_size: int = 10000):
    p = Path(csv_path)
    if not p.exists():
        print(f"[-] Error: File not found at {csv_path}")
        print("    Download the dataset from: https://www.kaggle.com/datasets/ealaxi/paysim1")
        return

    print("=" * 75)
    print(f" VaultDB Kaggle Importer: {p.name}")
    print(f" Target Import Limit: {limit:,} records")
    print("=" * 75)

    t0 = time.perf_counter()
    imported_count = 0

    with psycopg.connect(settings.postgres_admin_conninfo, autocommit=True) as conn:
        with conn.cursor() as cur:
            batch = []
            with open(p, mode="r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Map Kaggle columns to app_data.transactions
                    # Kaggle PaySim: step, type, amount, nameOrig, nameDest, isFraud
                    try:
                        amount = float(row.get("amount", 0.0))
                        t_type = row.get("type", "TRANSFER")
                        dest = row.get("nameDest", "Unknown Merchant")
                        is_fraud = row.get("isFraud", "0")
                        status = "flagged" if is_fraud == "1" else "completed"
                    except Exception:
                        continue

                    # Associate with an existing account ID (1 to 35)
                    account_id = (imported_count % 35) + 1
                    batch.append((account_id, t_type, amount, dest, status))
                    imported_count += 1

                    if len(batch) >= batch_size:
                        cur.executemany("""
                            INSERT INTO app_data.transactions (account_id, transaction_type, amount, merchant, status)
                            VALUES (%s, %s, %s, %s, %s);
                        """, batch)
                        batch.clear()
                        pct = (imported_count / limit) * 100
                        print(f" -> Imported {imported_count:,}/{limit:,} rows ({pct:.1f}%)...")

                    if imported_count >= limit:
                        break

                if batch:
                    cur.executemany("""
                        INSERT INTO app_data.transactions (account_id, transaction_type, amount, merchant, status)
                        VALUES (%s, %s, %s, %s, %s);
                    """, batch)

    elapsed = time.perf_counter() - t0
    rate = imported_count / elapsed if elapsed > 0 else 0
    print("\n" + "=" * 75)
    print(f"[+] Successfully imported {imported_count:,} Kaggle records in {elapsed:.2f}s ({rate:,.0f} rows/sec).")
    print("=" * 75)


def main():
    parser = argparse.ArgumentParser(description="Kaggle Dataset Importer for VaultDB")
    parser.add_argument("csv_path", type=str, help="Path to Kaggle CSV file (e.g. PS_20174392719_1491204439457_log.csv)")
    parser.add_argument("--limit", type=int, default=100000, help="Max records to import (default: 100,000)")
    parser.add_argument("--batch-size", type=int, default=10000, help="Batch insertion chunk size")
    args = parser.parse_args()

    import_paysim_csv(args.csv_path, limit=args.limit, batch_size=args.batch_size)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("""
Kaggle Financial Datasets Compatible with VaultDB:
==================================================
1. PaySim Synthetic Financial Dataset (6.3 Million Records)
   Kaggle URL: https://www.kaggle.com/datasets/ealaxi/paysim1
   File: PS_20174392719_1491204439457_log.csv

2. Credit Card Fraud Detection (284,807 Records)
   Kaggle URL: https://www.kaggle.com/datasets/mlg-ulb/creditcardfraud

To import, download the CSV and run:
  python scripts/import_kaggle_dataset.py <path_to_csv> --limit 100000
        """)
    else:
        main()
