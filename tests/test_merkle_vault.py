"""
Unit tests for VaultDB Native Cryptographic Merkle Tree Ledger.
Tests RFC 6962 binary Merkle trees, inclusion proofs, append-only disk ledger,
and cryptographic tamper detection.
"""

import json
import pytest
import tempfile
import shutil
from pathlib import Path

from src.vault_db.storage.merkle_vault import MerkleTree, MerkleVault


def test_merkle_tree_basic_hashing():
    """Validates RFC 6962 leaf hashing and internal node composition."""
    leaf_hash1 = MerkleTree.hash_leaf(b"query_1_data")
    leaf_hash2 = MerkleTree.hash_leaf(b"query_2_data")

    assert len(leaf_hash1) == 64
    assert len(leaf_hash2) == 64
    assert leaf_hash1 != leaf_hash2

    parent = MerkleTree.hash_internal(leaf_hash1, leaf_hash2)
    assert len(parent) == 64
    assert parent != leaf_hash1
    assert parent != leaf_hash2


def test_merkle_tree_inclusion_proofs():
    """Tests O(log N) inclusion proof generation and mathematical path verification."""
    tree = MerkleTree()
    leaves = [MerkleTree.hash_leaf(f"log_{i}".encode("utf-8")) for i in range(8)]

    for l in leaves:
        tree.append_leaf(l)

    root = tree.get_root()
    assert len(root) == 64

    # Verify each leaf generates a valid cryptographic audit path
    for idx, leaf_hash in enumerate(leaves):
        proof = tree.get_audit_path(idx)
        assert len(proof) == 3  # log2(8) = 3 levels
        assert MerkleTree.verify_proof(leaf_hash, proof, root) is True

        # Tampered leaf must fail verification
        tampered_leaf = leaf_hash[:-4] + "0000"
        assert MerkleTree.verify_proof(tampered_leaf, proof, root) is False


def test_merkle_vault_lifecycle_and_tamper_detection():
    """Tests end-to-end ledger logging, querying, and out-of-band disk tamper detection."""
    temp_dir = tempfile.mkdtemp()
    try:
        vault = MerkleVault(data_dir=temp_dir)

        # 1. Append records
        entry1 = vault.append_audit_log(
            app_user="alice@bank.com",
            user_role="employee",
            action="SELECT",
            target_table="accounts",
            query_text="SELECT balance FROM app_data.accounts WHERE id = 1;",
            execution_status="SUCCESS",
            execution_time_ms=1.25,
            is_sensitive=True,
            sensitive_fields=["balance"],
        )
        assert entry1["id"] == 1
        assert entry1["immudb_verified"] is True
        assert len(entry1["immudb_tx_hash"]) == 64

        entry2 = vault.append_audit_log(
            app_user="bob@bank.com",
            user_role="auditor",
            action="SELECT",
            target_table="audit_logs",
            query_text="SELECT * FROM vault_audit.audit_logs;",
            execution_status="SUCCESS",
            execution_time_ms=2.10,
        )
        assert entry2["id"] == 2

        # 2. Verify state and querying
        state = vault.get_ledger_state()
        assert state["tx_id"] == 2
        assert state["database"] == "native_merkle_ledger"
        assert state["verified"] is True

        logs = vault.get_audit_logs(limit=10)
        assert len(logs) == 2
        assert logs[0]["id"] == 2  # Reverse chronological
        assert logs[1]["id"] == 1

        # 3. Verify authentic cryptographic proof
        v1 = vault.verify_audit_log(1)
        assert v1["verified"] is True
        assert v1["tamper_detected"] is False

        v2 = vault.verify_audit_log(2)
        assert v2["verified"] is True
        assert v2["tamper_detected"] is False

        # 4. Simulate malicious on-disk tampering (e.g. Rogue DBA editing ledger file)
        ledger_path = Path(temp_dir) / "audit_ledger.jsonl"
        with open(ledger_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        tampered_entry = json.loads(lines[0])
        # Mutate query secretly without updating leaf hash
        tampered_entry["payload"]["query_text"] = "SELECT password FROM secret_table;"
        lines[0] = json.dumps(tampered_entry) + "\n"

        with open(ledger_path, "w", encoding="utf-8") as f:
            f.writelines(lines)

        # 5. Verify cryptographic proof catches the tampering
        tamper_check = vault.verify_audit_log(1)
        assert tamper_check["tamper_detected"] is True
        assert tamper_check["verified"] is False
        assert "TAMPER DETECTED" in tamper_check["message"]

        vault.close()

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def test_merkle_vault_state_recovery():
    """Tests that a restarted MerkleVault reconstructs its Merkle tree faithfully from disk."""
    temp_dir = tempfile.mkdtemp()
    try:
        vault1 = MerkleVault(data_dir=temp_dir)
        vault1.append_audit_log(
            app_user="alice@bank.com",
            user_role="admin",
            action="INSERT",
            target_table="users",
            query_text="INSERT INTO users VALUES ('alice');",
            execution_status="SUCCESS",
        )
        vault1.append_audit_log(
            app_user="charlie@bank.com",
            user_role="writer",
            action="UPDATE",
            target_table="accounts",
            query_text="UPDATE accounts SET status = 'active';",
            execution_status="SUCCESS",
        )
        root1 = vault1.get_ledger_state()["root_hash"]
        vault1.close()

        # Reopen in fresh instance
        vault2 = MerkleVault(data_dir=temp_dir)
        root2 = vault2.get_ledger_state()["root_hash"]

        assert root1 == root2
        assert vault2.get_ledger_state()["tx_id"] == 2
        vault2.close()

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
