"""
Audit Log Cryptographic Verification Utility (CLI Tool)
Mathematically verifies that audit records in immudb have not been modified or deleted.
Command-line equivalent of the 'Verify Proof' button on the web dashboard.
"""

import sys
import argparse
from pathlib import Path

# Add project root directory to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from src.vault_db.storage.immudb_vault import ImmudbVault


def verify_single(immudb: ImmudbVault, log_id: int) -> dict:
    """Verifies a single log entry against immudb's cryptographic Merkle tree."""
    result = immudb.verify_audit_log(log_id)
    
    if result.get("verified"):
        print(f"Log #{log_id}: VERIFIED (Authentic & Untampered)")
        print(f"  Transaction ID:   #{result.get('tx_id')}")
        print(f"  Merkle Root Hash: {result.get('current_root_hash')}")
    else:
        print(f"Log #{log_id}: FAILED (Tampering detected or record missing)")
        print(f"  Error: {result.get('error') or result.get('message')}")
        
    return result


def verify_all(immudb: ImmudbVault, limit: int = 10) -> list:
    """Audits the latest N log entries and displays a concise verification table."""
    logs = immudb.get_audit_logs(limit=limit)
    if not logs:
        print("No audit logs found in immudb ledger.")
        return []

    print(f"\nAuditing latest {len(logs)} entries in immudb:")
    print(f"{'ID':<6} {'STATUS':<10} {'USER':<24} {'ACTION':<10} {'INTEGRITY'}")

    for log in logs:
        log_id = log.get("id")
        check = immudb.verify_audit_log(log_id)
        status = "PASS" if check.get("verified") else "FAIL (Tampered)"
        
        user_str = str(log.get('user') or 'N/A')
        status_str = str(log.get('status') or 'N/A')
        action_str = str(log.get('action') or 'N/A')
        
        print(f"#{str(log_id):<5} {status_str:<10} {user_str:<24} {action_str:<10} {status}")

    return logs


def main():
    parser = argparse.ArgumentParser(description="VaultDB Cryptographic Audit Verifier")
    parser.add_argument("--log-id", type=int, help="Specific audit log ID to verify", default=None)
    parser.add_argument("--limit", type=int, help="Number of recent logs to audit", default=10)
    args = parser.parse_args()

    immudb = ImmudbVault()
    try:
        if args.log_id is not None:
            verify_single(immudb, args.log_id)
        else:
            verify_all(immudb, args.limit)
    finally:
        immudb.close()


if __name__ == "__main__":
    main()
