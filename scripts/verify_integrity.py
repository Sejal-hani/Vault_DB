"""
Audit Log Cryptographic Verification Utility (CLI Tool)
Mathematically verifies to compliance officers and auditors that logs in immudb have never been altered or deleted.
This is the command-line equivalent of the green 'Verify Proof' button on the web dashboard.
"""

import sys
import argparse
from pathlib import Path

# Add project root directory to sys.path so we can import ImmudbVault
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from src.vault_db.storage.immudb_vault import ImmudbVault


def verify_single(immudb: ImmudbVault, log_id: int):
    """
    Verifies a single audit log entry by its ID.
    Directly corresponds to clicking 'Verify Proof' on a specific row in the Dashboard.
    """
    print(f"\nVerifying cryptographic Merkle proof for Audit Log #{log_id}...")
    
    # Call the core immudb verification function (fetches entry + verifies SHA-256 Merkle root)
    result = immudb.verify_audit_log(log_id)

    if result.get("verified"):
        print(f"VERIFIED: Log #{log_id} is authentic and untampered.")
        print(f"immudb Key:       {result.get('immudb_key')}")
        print(f"Transaction ID:   #{result.get('tx_id')}")
        print(f"Merkle Root Hash: {result.get('current_root_hash')}")
        
        # Display the verified payload data
        record = result.get("record", {})
        print(f"User:             {record.get('app_user')} ({record.get('user_role')})")
        print(f"Action:           {record.get('action')} on table '{record.get('target_table')}'")
        print(f"Executed Query:   {record.get('query_text')}")
        print(f"Status:           {record.get('execution_status')}")
    else:
        print(f"FAILED: Cryptographic proof for Log #{log_id} could NOT be verified!")
        print(f"Reason: {result.get('error') or result.get('message')}")


def verify_all(immudb: ImmudbVault, limit: int = 10):
    """
    Audits the latest N entries and prints a summary verification table in the terminal.
    Corresponds to viewing the Audit Ledger table on the Dashboard.
    """
    print(f"\nAuditing latest {limit} immutable log entries in immudb...\n")
    logs = immudb.get_audit_logs(limit=limit)

    if not logs:
        print("No audit logs found in immudb ledger.")
        return

    # Table Header
    print(f"{'ID':<6} {'STATUS':<10} {'USER':<24} {'ACTION':<10} {'MERKLE VERIFICATION'}")

    for log in logs:
        log_id = log.get("id")
        
        # Verify each log's cryptographic Merkle proof
        check = immudb.verify_audit_log(log_id)
        if check.get("verified"):
            proof_status = "PASS (Merkle Match)"
        else:
            proof_status = "FAIL (Tampered/Corrupt)"

        status_str = str(log.get('status') or 'N/A')
        user_str = str(log.get('user') or 'N/A')
        action_str = str(log.get('action') or 'N/A')
        
        print(f"#{str(log_id):<5} {status_str:<10} {user_str:<24} {action_str:<10} {proof_status}")


def main():
    # Parse optional command line arguments: --log-id <number> or --limit <number>
    parser = argparse.ArgumentParser(description="VaultDB Cryptographic Audit Verifier (immudb CLI)")
    parser.add_argument("--log-id", type=int, help="Specific audit log ID to verify", default=None)
    parser.add_argument("--limit", type=int, help="Number of recent logs to audit (default: 10)", default=10)
    args = parser.parse_args()

    print("\n--- VaultDB: Cryptographic Integrity Auditor ---")

    try:
        # Step 1: Connect to the running immudb server
        immudb = ImmudbVault()
        state = immudb.get_ledger_state()
        print(f"Connected to immudb (Database: {state['database']}, Transaction Height: #{state['tx_id']})")
        print(f"Current State Merkle Root: {state['root_hash']}")

        # Step 2: Either verify a single log ID, or audit a batch of recent logs
        if args.log_id is not None:
            verify_single(immudb, args.log_id)
        else:
            verify_all(immudb, args.limit)

        immudb.close()

    except Exception as error:
        print(f"Verification error: {error}")


if __name__ == "__main__":
    main()
