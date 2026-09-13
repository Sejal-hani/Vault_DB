"""
VaultDB - Benchmark & Middleware Verification Script
Demonstrates normal queries, sensitive query detection, error handling,
and measures honest latency overhead (raw psycopg vs VaultClient).
"""
import time
import psycopg
from vault_client import VaultClient


def run_benchmark():
    print("=================================================================")
    print("VAULTDB MIDDLEWARE DEMO & BENCHMARK")
    print("=================================================================")

    client = VaultClient()

    # 1. Normal Query (Sarah / writer)
    print("\n[1] Executing Normal Query (Sarah / writer)...")
    res1 = client.execute(
        "SELECT name, email FROM app_data.customers",
        app_user="sarah@company.com",
        user_role="writer"
    )
    print(f"    Returned {len(res1)} rows: {res1}")

    # 2. Sensitive Query (John / admin)
    print("\n[2] Executing Sensitive Query touching SSN (John / admin)...")
    res2 = client.execute(
        "SELECT name, ssn FROM app_data.customers WHERE id = 1",
        app_user="john@company.com",
        user_role="admin"
    )
    print(f"    Returned {len(res2)} rows: {res2}")

    # 3. Broken Query Error Handling
    print("\n[3] Testing Broken Query (Syntax Error)...")
    try:
        client.execute(
            "SELECCC * FROM app_data.customers",
            app_user="attacker@bad.com",
            user_role="reader"
        )
    except Exception as err:
        print(f"    Caught expected database error: {err}")

    # 4. Latency Benchmark (100 queries)
    print("\n[4] Running 100-query Latency Benchmark...")
    N = 100

    # Baseline: direct raw psycopg (no auditing)
    conn_raw = psycopg.connect("host=127.0.0.1 port=5432 user=postgres dbname=postgres", autocommit=True)
    cur_raw = conn_raw.cursor()
    t0 = time.perf_counter()
    for _ in range(N):
        cur_raw.execute("SELECT * FROM app_data.customers WHERE id = 1")
        cur_raw.fetchall()
    raw_avg = (time.perf_counter() - t0) * 1000 / N
    conn_raw.close()

    # VaultClient middleware (parsing + query + audit log INSERT)
    t0 = time.perf_counter()
    for _ in range(N):
        client.execute(
            "SELECT * FROM app_data.customers WHERE id = 1",
            app_user="benchmark_user",
            user_role="reader"
        )
    mw_avg = (time.perf_counter() - t0) * 1000 / N

    print(f"    Raw psycopg (Direct DB):        {raw_avg:.3f} ms/query")
    print(f"    VaultClient (With Audit Log):    {mw_avg:.3f} ms/query")
    print(f"    Honest Middleware Overhead:      {mw_avg - raw_avg:.3f} ms/query")

    # 5. Display Latest Audit Logs from PostgreSQL
    print("\n[5] Latest Records in vault_audit.audit_logs:")
    print("    LOG_ID | USER              | ACTION | TABLE     | SENSITIVE | STATUS  | ROWS")
    print("    " + "-" * 70)
    for log in client.get_audit_logs(limit=5):
        log_id, _, user, role, action, table, sensitive, status, rows = log
        print(f"    {log_id:<6} | {user:<17} | {action:<6} | {table:<9} | {str(sensitive):<9} | {status:<7} | {rows}")

    client.close()
    print("\nDemo & Benchmark completed successfully!")


if __name__ == "__main__":
    run_benchmark()
