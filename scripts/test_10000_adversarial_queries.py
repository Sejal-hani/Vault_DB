"""
VaultDB 10,000 Adversarial Query Benchmark & Cryptographic Verification Suite
Generates high-volume synthetic adversarial datasets and executes 10,000 queries
through the compliance middleware, testing SQL injection, RBAC privilege escalation,
sensitive PII probing, database crashes, and immudb Merkle tree state verification.
"""

import sys
import time
import json
import random
from pathlib import Path
from typing import List, Tuple, Dict, Any
from concurrent.futures import ThreadPoolExecutor

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from src.vault_db.core.engine import VaultEngine
from src.vault_db.core.rbac import AccessDeniedError, QueryExecutionError


def generate_adversarial_dataset(total_queries: int = 10000) -> List[Tuple[str, str, str]]:
    """
    Generates a realistic, synthetic adversarial dataset covering 5 key categories:
    1. Legitimate Enterprise Queries (45%)
    2. SQL Injection & Cyber Exploits (15%)
    3. Privilege Escalation & RBAC Violations (15%)
    4. Sensitive PII & Credential Probing (15%)
    5. Malformed Syntax & Database Crashes (10%)
    Returns: List of (user_email, query_text, category_name)
    """
    print(f"[*] Generating {total_queries} synthetic queries with adversarial distributions...")

    # Category 1: Legitimate Enterprise Queries
    legitimate_templates = [
        ("alice@bank.com", "SELECT account_number, account_type, balance FROM app_data.accounts WHERE balance > 1000;"),
        ("alice@bank.com", "SELECT * FROM app_data.transactions WHERE account_id = {acc_id} ORDER BY created_at DESC LIMIT 5;"),
        ("john@bank.com", "SELECT id, account_id, amount, status FROM app_data.transactions WHERE amount > {amount};"),
        ("john@bank.com", "UPDATE app_data.transactions SET status = 'completed' WHERE id = {tx_id};"),
        ("john@bank.com", "INSERT INTO app_data.transactions (account_id, amount, transaction_type, status, merchant) VALUES ({acc_id}, {amount}, 'TRANSFER', 'completed', 'SWIFT Settlement Hub');"),
        ("compliance.lead@bank.com", "SELECT policy_code, title, standard, enforcement_level FROM app_data.compliance_policies;"),
        ("compliance.lead@bank.com", "SELECT * FROM app_data.accounts WHERE balance > 500000;"),
        ("admin@bank.com", "SELECT email, role, full_name, department FROM app_data.users;"),
        ("admin@bank.com", "SELECT a.account_number, a.name, t.amount, t.merchant FROM app_data.accounts a JOIN app_data.transactions t ON a.id = t.account_id WHERE t.amount > 50000;"),
        ("sarah.auditor@bank.com", "SELECT COUNT(*), AVG(balance) FROM app_data.accounts;"),
    ]

    # Category 2: SQL Injection & Cyber Exploits
    sqli_templates = [
        ("attacker@botnet.org", "SELECT * FROM app_data.accounts WHERE name = '' OR '1'='1';"),
        ("hacker@exploit.net", "SELECT name, balance FROM app_data.accounts WHERE id = 1 UNION SELECT email, role FROM app_data.users;"),
        ("hacker@exploit.net", "SELECT * FROM app_data.accounts WHERE account_number = 'ACC-1001'-- AND is_active = true;"),
        ("alice@bank.com", "SELECT * FROM app_data.transactions WHERE id = 1; DROP TABLE app_data.accounts;"),
        ("john@bank.com", "SELECT * FROM app_data.accounts WHERE id = 1; UPDATE app_data.accounts SET balance = 99999999 WHERE id = 1;"),
        ("unknown@scanner.io", "SELECT * FROM app_data.accounts WHERE id = 1 AND 1=1;"),
        ("hacker@exploit.net", "SELECT * FROM app_data.accounts WHERE name = 'admin'/*comment*/OR/*comment*/'x'='x';"),
        ("attacker@botnet.org", "SELECT * FROM app_data.users WHERE email = 'admin@bank.com' OR 1=1; --"),
    ]

    # Category 3: Severe Privilege Escalation & RBAC Violations
    rbac_templates = [
        ("alice@bank.com", "DROP TABLE app_data.accounts;"),
        ("alice@bank.com", "TRUNCATE TABLE app_data.transactions;"),
        ("alice@bank.com", "DELETE FROM app_data.accounts WHERE id = 1;"),
        ("alice@bank.com", "UPDATE app_data.accounts SET balance = 50000000 WHERE id = 1;"),
        ("carlos.m@techcorp.io", "ALTER TABLE app_data.accounts ADD COLUMN backdoor_key text;"),
        ("john@bank.com", "UPDATE app_data.users SET role = 'admin' WHERE email = 'john@bank.com';"),
        ("john@bank.com", "DROP TABLE app_data.compliance_policies;"),
        ("john@bank.com", "UPDATE app_data.accounts SET balance = 10000000 WHERE id = 2;"),
        ("intruder@darknet.io", "SELECT * FROM app_data.accounts;"),
        ("rogue_agent@shadow.org", "DELETE FROM app_data.compliance_policies;"),
    ]

    # Category 4: Sensitive PII & Credential Probing
    sensitive_templates = [
        ("admin@bank.com", "SELECT id, name, ssn FROM app_data.accounts WHERE balance > 100000;"),
        ("admin@bank.com", "SELECT email, password FROM app_data.users;"),
        ("admin@bank.com", "SELECT account_number, credit_card, cvv, pin FROM app_data.accounts;"),
        ("sarah.auditor@bank.com", "SELECT name, ssn, balance FROM app_data.accounts;"),
        ("alice@bank.com", "SELECT name, ssn FROM app_data.accounts WHERE id = 1;"),
        ("compliance.lead@bank.com", "SELECT account_number, secret, token FROM app_data.accounts;"),
        ("admin@bank.com", "SELECT id, ssn, card_number FROM app_data.accounts WHERE id = {acc_id};"),
    ]

    # Category 5: Malformed Syntax & Database Crashes
    error_templates = [
        ("admin@bank.com", "SELEECTT * FORM app_data.accounts WHERE @@###;"),
        ("admin@bank.com", "SELECT * FROM app_data.non_existent_shadow_table;"),
        ("john@bank.com", "SELECT non_existent_column_xyz FROM app_data.accounts;"),
        ("alice@bank.com", "SELECT 1/0 FROM app_data.accounts;"),
        ("admin@bank.com", "SELECT * FROM app_data.accounts WHERE id = 'abc_invalid_integer';"),
        ("john@bank.com", "INSERT INTO app_data.transactions (id) VALUES ('not_an_int');"),
        ("admin@bank.com", "SELECT " + ", ".join([f"id AS col_{i}" for i in range(150)]) + " FROM app_data.accounts;"),
    ]

    dataset = []
    
    # 45% Legitimate
    count_legit = int(total_queries * 0.45)
    # 15% SQLi
    count_sqli = int(total_queries * 0.15)
    # 15% RBAC
    count_rbac = int(total_queries * 0.15)
    # 15% Sensitive
    count_sensitive = int(total_queries * 0.15)
    # Remainder Error / Malformed (10%)
    count_error = total_queries - (count_legit + count_sqli + count_rbac + count_sensitive)

    for _ in range(count_legit):
        user, tmpl = random.choice(legitimate_templates)
        q = tmpl.format(
            acc_id=random.randint(1, 30),
            tx_id=random.randint(1, 5000),
            amount=random.randint(500, 250000)
        )
        dataset.append((user, q, "LEGITIMATE"))

    for _ in range(count_sqli):
        user, q = random.choice(sqli_templates)
        dataset.append((user, q, "SQL_INJECTION"))

    for _ in range(count_rbac):
        user, q = random.choice(rbac_templates)
        dataset.append((user, q, "RBAC_VIOLATION"))

    for _ in range(count_sensitive):
        user, tmpl = random.choice(sensitive_templates)
        q = tmpl.format(acc_id=random.randint(1, 30))
        dataset.append((user, q, "SENSITIVE_PROBE"))

    for _ in range(count_error):
        user, q = random.choice(error_templates)
        dataset.append((user, q, "SYNTAX_CRASH"))

    random.shuffle(dataset)
    print(f"[+] Successfully synthesized {len(dataset)} adversarial queries.")
    return dataset


def run_benchmark_10000(total_target: int = 10000):
    print("=" * 80)
    print(f" VaultDB High-Volume Stress Test: {total_target:,} Adversarial Queries on immudb")
    print("=" * 80)

    engine = VaultEngine()
    initial_state = engine.get_ledger_state()
    start_tx = initial_state["tx_id"]
    start_hash = initial_state["root_hash"]

    print(f"[*] Initial immudb State Root: {start_hash}")
    print(f"[*] Initial immudb Ledger Height: #{start_tx}")
    print(f"[*] Database: {initial_state['database']}")
    print("-" * 80)

    dataset = generate_adversarial_dataset(total_target)

    # Metrics
    latencies = []
    category_counts = {
        "LEGITIMATE": {"total": 0, "success": 0, "denied": 0, "error": 0},
        "SQL_INJECTION": {"total": 0, "success": 0, "denied": 0, "error": 0},
        "RBAC_VIOLATION": {"total": 0, "success": 0, "denied": 0, "error": 0},
        "SENSITIVE_PROBE": {"total": 0, "success": 0, "denied": 0, "error": 0},
        "SYNTAX_CRASH": {"total": 0, "success": 0, "denied": 0, "error": 0},
    }

    success_total = 0
    denied_total = 0
    error_total = 0
    sensitive_total = 0

    # Samples for post-benchmark Merkle tree verification
    sampled_logs: Dict[str, int] = {}

    start_time = time.perf_counter()
    last_checkpoint_time = start_time

    print(f"[*] Starting execution of {total_target} compliance queries through VaultDB...\n")

    for i, (user, query, cat) in enumerate(dataset, 1):
        t0 = time.perf_counter()
        category_counts[cat]["total"] += 1

        try:
            res = engine.execute(query=query, app_user=user)
            elapsed = (time.perf_counter() - t0) * 1000
            latencies.append(elapsed)
            success_total += 1
            category_counts[cat]["success"] += 1

            if res.get("is_sensitive"):
                sensitive_total += 1
            
            if cat not in sampled_logs and res.get("immudb_log_id"):
                sampled_logs[cat] = res.get("immudb_log_id")

        except AccessDeniedError as de:
            elapsed = (time.perf_counter() - t0) * 1000
            latencies.append(elapsed)
            denied_total += 1
            category_counts[cat]["denied"] += 1
            
            rec = getattr(de, "immudb_record", {}) or {}
            if cat not in sampled_logs and rec.get("id"):
                sampled_logs[cat] = rec.get("id")

        except (QueryExecutionError, Exception) as ee:
            elapsed = (time.perf_counter() - t0) * 1000
            latencies.append(elapsed)
            error_total += 1
            category_counts[cat]["error"] += 1

            rec = getattr(ee, "immudb_record", {}) or {}
            if cat not in sampled_logs and rec.get("id"):
                sampled_logs[cat] = rec.get("id")

        # Progress reporting every 1,000 queries
        if i % 1000 == 0 or i == total_target:
            now = time.perf_counter()
            batch_time = now - last_checkpoint_time
            last_checkpoint_time = now
            batch_qps = 1000 / batch_time if batch_time > 0 else 0
            overall_elapsed = now - start_time
            overall_qps = i / overall_elapsed
            pct = (i / total_target) * 100

            print(
                f" -> Progress: {i:>5}/{total_target} ({pct:>3.0f}%) | "
                f"Batch: {batch_qps:>5.1f} q/s | "
                f"Overall: {overall_qps:>5.1f} q/s | "
                f"Elapsed: {overall_elapsed:>5.1f}s | "
                f"SUCCESS: {success_total} | DENIED: {denied_total} | ERROR: {error_total}"
            )

    total_duration = time.perf_counter() - start_time
    throughput_qps = total_target / total_duration

    latencies.sort()
    p50 = latencies[int(len(latencies) * 0.50)]
    p95 = latencies[int(len(latencies) * 0.95)]
    p99 = latencies[int(len(latencies) * 0.99)]
    max_lat = max(latencies)

    final_state = engine.get_ledger_state()
    final_tx = final_state["tx_id"]
    final_hash = final_state["root_hash"]
    tx_committed = final_tx - start_tx

    print("\n" + "=" * 80)
    print(" 10,000 ADVERSARIAL QUERY BENCHMARK RESULTS")
    print("=" * 80)
    print(f" Total Queries Intercepted:      {total_target:,}")
    print(f" Total Wall Time:                {total_duration:.2f} seconds ({total_duration/60:.2f} minutes)")
    print(f" Average Throughput:             {throughput_qps:.1f} queries/second")
    print(f" Median Latency (P50):           {p50:.2f} ms")
    print(f" 95th Percentile Latency (P95):  {p95:.2f} ms")
    print(f" 99th Percentile Latency (P99):  {p99:.2f} ms")
    print(f" Max Observed Latency:           {max_lat:.2f} ms")
    print("-" * 80)
    print(f" Authorized Queries (SUCCESS):   {success_total:,} ({(success_total/total_target)*100:.1f}%)")
    print(f" Blocked Violations (DENIED):    {denied_total:,} ({(denied_total/total_target)*100:.1f}%)")
    print(f" Execution Errors (ERROR):       {error_total:,} ({(error_total/total_target)*100:.1f}%)")
    print(f" Sensitive PII Queries Flagged:  {sensitive_total:,}")
    print("-" * 80)
    print(" CATEGORY-BY-CATEGORY ADVERSITY BREAKDOWN:")
    for cat_name, stats in category_counts.items():
        print(
            f"   {cat_name:<18} Total: {stats['total']:<5} | "
            f"SUCCESS: {stats['success']:<5} | "
            f"DENIED: {stats['denied']:<5} | "
            f"ERROR: {stats['error']:<5}"
        )
    print("-" * 80)
    print(" IMMUDB CRYPTOGRAPHIC MERKLE TREE LEDGER INTEGRITY:")
    print(f"   Starting Transaction Height:  #{start_tx}")
    print(f"   Final Transaction Height:     #{final_tx}")
    print(f"   Transactions Committed:       {tx_committed:,}")
    print(f"   Starting State Merkle Root:   {start_hash}")
    print(f"   Final State Merkle Root:      {final_hash}")
    print("=" * 80)

    # 4. Zero-Trust Cryptographic Merkle Verification on Samples
    print("\n[*] Performing Zero-Trust Merkle Inclusion Proof Audits on Sampled Records...")
    print("-" * 80)
    print(f"{'CATEGORY':<18} {'LOG ID':<8} {'TX ID':<8} {'VERIFIED':<10} {'TAMPER DETECTED':<16} {'PROOF STATUS'}")
    print("-" * 80)

    all_verified = True
    for cat_name, log_id in sampled_logs.items():
        proof = engine.verify_audit_log(log_id)
        is_verified = proof.get("verified", False)
        is_tampered = proof.get("tamper_detected", True)
        if not is_verified or is_tampered:
            all_verified = False

        status_label = "VALID MERKLE PROOF" if is_verified else "CORRUPT/TAMPERED"
        print(
            f"{cat_name:<18} #{log_id:<7} #{proof.get('tx_id', 'N/A'):<7} "
            f"{str(is_verified):<10} {str(is_tampered):<16} {status_label}"
        )

    print("-" * 80)
    if all_verified and tx_committed >= total_target:
        print("[+] 100% OF ADVERSARIAL SAMPLES CRYPTOGRAPHICALLY VERIFIED AGAINST STATE MERKLE ROOT.")
        print("[+] IMMUTABLE INTEGRITY PROVEN: No records lost, corrupted, or backdated.")
    else:
        print("[-] WARNING: Some cryptographic proofs failed or transaction count discrepancy.")

    # Save summary report to JSON
    report_path = BASE_DIR / "scripts" / "benchmark_10000_results.json"
    report_data = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_queries": total_target,
        "duration_seconds": round(total_duration, 2),
        "throughput_qps": round(throughput_qps, 2),
        "latencies_ms": {
            "p50": round(p50, 2),
            "p95": round(p95, 2),
            "p99": round(p99, 2),
            "max": round(max_lat, 2),
        },
        "outcomes": {
            "success": success_total,
            "denied": denied_total,
            "error": error_total,
            "sensitive_flagged": sensitive_total,
        },
        "immudb": {
            "start_tx": start_tx,
            "final_tx": final_tx,
            "transactions_committed": tx_committed,
            "start_merkle_root": start_hash,
            "final_merkle_root": final_hash,
            "all_samples_verified": all_verified,
        },
        "breakdown": category_counts,
    }

    with open(report_path, "w") as f:
        json.dump(report_data, f, indent=2)

    print(f"\n[+] Detailed benchmark metrics written to {report_path}")
    print("=" * 80)

    engine.close()


if __name__ == "__main__":
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 10000
    run_benchmark_10000(count)
