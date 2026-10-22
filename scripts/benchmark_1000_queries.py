"""
High-Volume Benchmark Test Script (1,000+ Queries)
Tests query throughput, latency, RBAC access control, and immudb cryptographic commitments.
Satisfies Project Deliverable: 'Tested with 1,000+ queries'.
"""

import sys
import time
import random
from pathlib import Path

# Add project root directory to sys.path so we can import VaultEngine
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from src.vault_db.core.engine import VaultEngine
from src.vault_db.core.rbac import AccessDeniedError


def run_benchmark(num_queries: int = 1000):
    print(f"\n--- Starting VaultDB Benchmark: {num_queries} Queries ---")

    # Step 1: Initialize the middleware engine and record starting immudb state
    engine = VaultEngine()
    initial_state = engine.get_ledger_state()
    print(f"Starting immudb Transaction Height: #{initial_state['tx_id']}")
    print(f"Starting Merkle Root Hash:          {initial_state['root_hash']}\n")

    # Step 2: Define a pool of realistic enterprise queries
    # Includes standard queries, RBAC security violations, and sensitive data queries
    test_queries = [
        # Normal authorized queries
        ("alice@bank.com", "SELECT * FROM app_data.accounts;"),
        ("alice@bank.com", "SELECT * FROM app_data.transactions WHERE account_id = 1;"),
        ("john@bank.com", "SELECT name, balance FROM app_data.accounts;"),
        ("john@bank.com", "UPDATE app_data.transactions SET status = 'pending' WHERE id = 1;"),
        ("admin@bank.com", "SELECT email, role FROM app_data.users;"),

        # Prohibited queries (RBAC Violations: should be blocked)
        ("john@bank.com", "UPDATE app_data.accounts SET balance = 99999 WHERE id = 1;"),
        ("alice@bank.com", "INSERT INTO app_data.transactions (account_id, amount) VALUES (1, 500);"),

        # Sensitive field queries (should be flagged as sensitive)
        ("admin@bank.com", "SELECT email, password FROM app_data.users;"),
    ]

    # Counters to track benchmark statistics
    latencies = []
    success_count = 0
    denied_count = 0
    sensitive_count = 0

    # Step 3: Run the benchmark loop and measure execution time
    start_time = time.perf_counter()

    for i in range(1, num_queries + 1):
        # Pick a random user and query from our test pool
        user, query = random.choice(test_queries)
        
        # Measure time taken for this query in milliseconds
        query_start = time.perf_counter()

        try:
            # Execute query through full VaultDB middleware pipeline
            result = engine.execute(query=query, app_user=user)
            elapsed_ms = (time.perf_counter() - query_start) * 1000
            latencies.append(elapsed_ms)
            success_count += 1
            if result.get("is_sensitive"):
                sensitive_count += 1

        except AccessDeniedError:
            # Expected security rejection for unauthorized queries
            elapsed_ms = (time.perf_counter() - query_start) * 1000
            latencies.append(elapsed_ms)
            denied_count += 1

        except Exception:
            # Any other expected database errors
            elapsed_ms = (time.perf_counter() - query_start) * 1000
            latencies.append(elapsed_ms)

        # Print progress every 200 queries
        if i % 200 == 0 or i == num_queries:
            percentage = (i / num_queries) * 100
            print(f"Progress: {i}/{num_queries} queries completed ({percentage:.0f}%)")

    # Step 4: Calculate performance metrics
    total_duration = time.perf_counter() - start_time
    queries_per_second = num_queries / total_duration

    # Calculate latency percentiles (Median P50, P95, P99)
    latencies.sort()
    p50_latency = latencies[int(len(latencies) * 0.50)]  # 50% of queries faster than this
    p95_latency = latencies[int(len(latencies) * 0.95)]  # 95% of queries faster than this
    p99_latency = latencies[int(len(latencies) * 0.99)]  # 99% of queries faster than this

    # Step 5: Read final immudb state to verify transactions committed
    final_state = engine.get_ledger_state()
    total_committed = final_state['tx_id'] - initial_state['tx_id']

    # Step 6: Print clean summary report
    print("\n--- Benchmark Performance Results ---")
    print(f"Total Queries Executed:       {num_queries}")
    print(f"Total Time Taken:             {total_duration:.2f} seconds")
    print(f"Throughput:                   {queries_per_second:.1f} queries/second")
    print(f"Median Latency (P50):         {p50_latency:.2f} ms")
    print(f"95th Percentile Latency (P95):{p95_latency:.2f} ms")
    print(f"99th Percentile Latency (P99):{p99_latency:.2f} ms")
    print(f"Authorized Queries (SUCCESS): {success_count}")
    print(f"Blocked Violations (DENIED):  {denied_count}")
    print(f"Sensitive Queries Flagged:    {sensitive_count}")
    print(f"Starting immudb Height:       #{initial_state['tx_id']}")
    print(f"Final immudb Height:          #{final_state['tx_id']}")
    print(f"Transactions Committed:       {total_committed}")
    print(f"Final Merkle Root Hash:       {final_state['root_hash']}")

    # Step 7: Cryptographically verify the last committed transaction
    print("\nVerifying cryptographic proof on latest committed record...")
    recent_logs = engine.get_audit_logs(limit=1)
    if recent_logs:
        proof = engine.verify_audit_log(recent_logs[0]["id"])
        print(f"Merkle Proof Valid:           {proof['verified']}")
        print(f"Tamper Detected:              {proof['tamper_detected']}")

    engine.close()


if __name__ == "__main__":
    # Allow user to specify custom query count from command line, default is 1000
    query_count = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    run_benchmark(query_count)
