"""
Integration Tests for immudb Cryptographic Ledger
"""

from src.vault_db.storage.immudb_vault import ImmudbVault


def test_immudb_verified_operations():
    vault = ImmudbVault()

    # 1. State check
    initial_state = vault.get_ledger_state()
    assert initial_state["verified"] is True
    assert initial_state["tx_id"] > 0
    assert len(initial_state["root_hash"]) > 0

    # 2. Append verified log
    record = vault.append_audit_log(
        app_user="test_runner@bank.com",
        user_role="admin",
        action="SELECT",
        target_table="accounts",
        query_text="SELECT 1;",
        execution_status="SUCCESS",
        execution_time_ms=1.5,
        is_sensitive=False,
    )

    assert record["id"] > 0
    assert record["immudb_verified"] is True
    assert record["immudb_tx_id"] >= initial_state["tx_id"]

    # 3. Cryptographic Merkle proof verification
    proof = vault.verify_audit_log(record["id"])
    assert proof["verified"] is True
    assert proof["tamper_detected"] is False
    assert proof["log_id"] == record["id"]
    assert proof["record"]["app_user"] == "test_runner@bank.com"

    vault.close()


def test_immudb_read_logs():
    vault = ImmudbVault()
    logs = vault.get_audit_logs(limit=5)
    assert isinstance(logs, list)
    assert len(logs) > 0
    vault.close()
