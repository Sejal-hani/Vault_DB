"""
Audit Log Cryptographic Verification Utility
Proves mathematically to compliance auditors that audit logs in immudb are untampered.
"""

import sys
import argparse
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from src.vault_db.storage.immudb_vault import ImmudbVault


def verify_single(immudb: ImmudbVault, log_id: int):
    print(f"[*] Verifying cryptographic proof for Audit Log #{log_id}...")
    res = immudb.verify_audit_log(log_id)

    if res.get("verified"):
        print(f"[+] VERIFIED: Log #{log_id} is AUTHENTIC and UNTAMPERED.")
        print(f"    immudb Key:         {res.get('immudb_key')}")
        print(f"    Transaction ID:     #{res.get('tx_id')}")
        print(f"    Merkle Root Hash:   {res.get('current_root_hash')}")
        record = res.get("record", {})
        print(f"    User:               {record.get('app_user')} ({record.get('user_role')})")
        print(f"    Action:             {record.get('action')} on {record.get('target_table')}")
        print(f"    Query:              {record.get('query_text')}")
        print(f"    Status:             {record.get('execution_status')}")
    else:
        print(f"[-] FAILED: Cryptographic proof for Log #{log_id} could NOT be verified!")
        print(f"    Error: {res.get('error') or res.get('message')}")


def verify_all(immudb: ImmudbVault, limit: int = 10):
    print(f"[*] Auditing latest {limit} immutable entries in immudb...")
    logs = immudb.get_audit_logs(limit=limit)

    if not logs:
        print("[-] No audit logs found in immudb ledger.")
        return

    print("-" * 80)
    print(f"{'ID':<6} {'STATUS':<10} {'USER':<20} {'ACTION':<10} {'IMMUTABLE PROOF'}")
    print("-" * 80)

    for l in logs:
        log_id = l.get("id")
        check = immudb.verify_audit_log(log_id)
        if check.get("verified"):
            proof_status = "VERIFIED (Merkle Match)"
        else:
            proof_status = "INVALID (Tampered/Corrupt)"

        status_str = str(l.get('status') or 'N/A')
        user_str = str(l.get('user') or 'N/A')
        action_str = str(l.get('action') or 'N/A')
        print(
            f"#{str(log_id):<5} {status_str:<10} {user_str:<20} "
            f"{action_str:<10} {proof_status}"
        )
    print("-" * 80)


def main():
    parser = argparse.ArgumentParser(description="VaultDB Cryptographic Audit Verifier (immudb)")
    parser.add_argument("--log-id", type=int, help="Specific audit log ID to verify", default=None)
    parser.add_argument("--limit", type=int, help="Number of recent logs to audit", default=10)
    args = parser.parse_args()

    print("=" * 80)
    print(" VaultDB: immudb Cryptographic Integrity & Proof Auditor")
    print("=" * 80)

    try:
        immudb = ImmudbVault()
        state = immudb.get_ledger_state()
        print(f"[+] Connected to immudb (Database: {state['database']}, Ledger Height: #{state['tx_id']})")
        print(f"    State Merkle Root: {state['root_hash']}\n")

        if args.log_id is not None:
            verify_single(immudb, args.log_id)
        else:
            verify_all(immudb, args.limit)

        immudb.close()
    except Exception as e:
        print(f"[-] Verification process encountered an error: {e}")

    print("=" * 80)


if __name__ == "__main__":
    main()
