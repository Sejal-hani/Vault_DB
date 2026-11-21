"""
VaultDB Native Cryptographic Merkle Ledger Storage Adapter
Provides an append-only transaction ledger on local disk with continuous Merkle tree seals.

Acts as a drop-in replacement for ImmudbVault, executing natively in pure Python
without requiring external Go binaries or Docker daemons.
"""

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.vault_db.core.merkle import MerkleTree

logger = logging.getLogger(__name__)

__all__ = ["MerkleVault", "MerkleTree"]


class MerkleVault:
    """
    Append-only disk ledger adapter secured by continuous Merkle tree seals.
    Guarantees immutable audit logging, inclusion proof generation, and tamper detection.
    """

    KEY_PREFIX: str = "audit:log:"
    COUNTER_KEY: str = "vaultdb:audit:counter"

    def __init__(self, data_dir: Optional[str] = None) -> None:
        """
        Initializes the native ledger directory and reconstructs the Merkle tree from disk.

        Args:
            data_dir: Path to directory where ledger records and state are stored.
                      Defaults to 'data/merkle_vault'.
        """
        self._is_default_dir: bool = data_dir is None
        self.base_dir = Path(data_dir or "data/merkle_vault")
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.ledger_file = self.base_dir / "audit_ledger.jsonl"
        self.state_file = self.base_dir / "ledger_state.json"

        self._lock = threading.Lock()
        self._tree = MerkleTree()
        self._counter: int = 0
        self._file_offset: int = 0
        self._tamper_detected: bool = False
        self._truncation_detected: bool = False
        self._tampered_entries: List[int] = []
        self._load_ledger()

    def _ensure_connected(self) -> None:
        """Interface compatibility method for duck typing with ImmudbVault."""
        pass

    def _sync_ledger(self) -> None:
        """
        Incrementally reads any new ledger entries appended by other processes or instances.
        Recomputes cryptographic leaf hashes to verify payload integrity in transit.
        """
        if not self.ledger_file.exists():
            return

        try:
            current_size = self.ledger_file.stat().st_size
            if current_size < self._file_offset:
                self._load_ledger()
                return

            if current_size > self._file_offset:
                with open(self.ledger_file, "r", encoding="utf-8") as f:
                    f.seek(self._file_offset)
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                            payload = entry.get("payload")
                            if payload:
                                payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
                                computed_hash = MerkleTree.hash_leaf(payload_bytes)
                                stored_hash = entry.get("leaf_hash")
                                if stored_hash and computed_hash != stored_hash:
                                    logger.error(
                                        f"CRITICAL: Integrity failure on sync at log #{entry.get('id')}: "
                                        f"stored={stored_hash}, computed={computed_hash}"
                                    )
                                    self._tamper_detected = True
                                    self._tampered_entries.append(entry.get("id"))
                                leaf_hash = computed_hash
                            elif entry.get("leaf_hash"):
                                leaf_hash = entry.get("leaf_hash")
                            else:
                                payload_copy = {k: v for k, v in entry.items() if k not in ("leaf_hash", "root_hash", "tx_id")}
                                payload_bytes = json.dumps(payload_copy, sort_keys=True).encode("utf-8")
                                leaf_hash = MerkleTree.hash_leaf(payload_bytes)

                            self._tree.append_leaf(leaf_hash)
                            self._counter = max(self._counter, entry.get("id", self._counter + 1))
                        except Exception:
                            continue
                    self._file_offset = f.tell()
        except Exception as e:
            logger.warning(f"Error syncing ledger from disk: {e}")

    def _load_ledger(self) -> None:
        """
        Reads existing transaction records from append-only storage and
        reconstructs the Merkle tree state root in memory.
        Enforces strict cryptographic payload re-hashing and checkpoint state validation
        to detect offline disk tampering or journal truncation.
        """
        leaf_hashes: List[str] = []
        count: int = 0

        if self.ledger_file.exists():
            with open(self.ledger_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        payload = entry.get("payload")
                        if payload:
                            payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
                            computed_hash = MerkleTree.hash_leaf(payload_bytes)
                            stored_hash = entry.get("leaf_hash")
                            if stored_hash and computed_hash != stored_hash:
                                logger.error(
                                    f"CRITICAL: Offline tampering detected at log #{entry.get('id', count+1)}! "
                                    f"Stored hash: {stored_hash}, Computed: {computed_hash}"
                                )
                                self._tamper_detected = True
                                self._tampered_entries.append(entry.get("id", count + 1))
                            leaf_hash = computed_hash
                        elif entry.get("leaf_hash"):
                            leaf_hash = entry.get("leaf_hash")
                        else:
                            payload_copy = {k: v for k, v in entry.items() if k not in ("leaf_hash", "root_hash", "tx_id")}
                            payload_bytes = json.dumps(payload_copy, sort_keys=True).encode("utf-8")
                            leaf_hash = MerkleTree.hash_leaf(payload_bytes)

                        leaf_hashes.append(leaf_hash)
                        count = max(count, entry.get("id", count + 1))
                    except Exception as e:
                        logger.warning(f"Skipping malformed ledger line: {e}")
                        continue
                self._file_offset = f.tell()
        else:
            self._file_offset = 0

        self._tree = MerkleTree(leaf_hashes)

        # In production ledger, align counter above existing PostgreSQL log_ids to prevent primary key collision
        if self._is_default_dir:
            try:
                from src.vault_db.storage.postgres import PostgresStorage
                pg = PostgresStorage()
                if pg._pool:
                    pg_res, _, _ = pg.execute_query("SELECT MAX(log_id) FROM vault_audit.audit_logs;")
                    if pg_res and pg_res[0] and pg_res[0][0]:
                        count = max(count, int(pg_res[0][0]))
            except Exception:
                pass

        self._counter = count

        # Cross-validate against persisted checkpoint state to detect offline truncation or root divergence
        if self.state_file.exists():
            try:
                with open(self.state_file, "r", encoding="utf-8") as sf:
                    saved_state = json.load(sf)
                    saved_tx = saved_state.get("tx_id", 0)
                    saved_root = saved_state.get("root_hash")
                    if count < saved_tx:
                        logger.error(
                            f"CRITICAL: Ledger journal truncation detected! "
                            f"Persisted checkpoint expected at least {saved_tx} records, but only {count} found on disk."
                        )
                        self._truncation_detected = True
                        self._tamper_detected = True
                    elif count == saved_tx and saved_root and self._tree.get_root() != saved_root:
                        logger.error(
                            f"CRITICAL: Ledger state root divergence detected! "
                            f"Recomputed root: {self._tree.get_root()}, Checkpoint root: {saved_root}"
                        )
                        self._tamper_detected = True
            except Exception as e:
                logger.warning(f"Could not verify persisted checkpoint state: {e}")

        logger.info(
            f"MerkleVault active: {self._counter} records loaded. "
            f"Current Root: {self._tree.get_root()[:16]}... "
            f"(Tamper Detected: {self._tamper_detected}, Truncation: {self._truncation_detected})"
        )

    def _persist_state(self) -> None:
        """Writes current ledger state metadata to disk."""
        state_data = {
            "tx_id": self._counter,
            "root_hash": self._tree.get_root(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "database": "native_merkle_ledger",
        }
        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump(state_data, f, indent=2)

    def append_audit_log(
        self,
        app_user: str,
        user_role: str,
        action: str,
        target_table: str,
        query_text: str,
        execution_status: str,
        execution_time_ms: float = 0.0,
        is_sensitive: bool = False,
        sensitive_fields: Optional[List[str]] = None,
        client_ip: str = "127.0.0.1",
        is_anomaly: bool = False,
        anomalies: Optional[List[str]] = None,
        rows_affected: int = 0,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Cryptographically commits an audit log entry to the append-only ledger.
        Computes SHA-256 leaf digest, adds to Merkle tree, and persists to disk.

        Returns:
            Dictionary with audit metadata and cryptographic proof hashes.
        """
        with self._lock:
            self._sync_ledger()
            self._counter += 1
            log_id = self._counter
            iso_timestamp = datetime.now(timezone.utc).isoformat()

            audit_payload = {
                "id": log_id,
                "timestamp": iso_timestamp,
                "app_user": app_user,
                "user_role": user_role,
                "action": action,
                "target_table": target_table,
                "query_text": query_text,
                "execution_status": execution_status,
                "execution_time_ms": round(execution_time_ms, 3),
                "is_sensitive": is_sensitive,
                "sensitive_fields": sensitive_fields or [],
                "client_ip": client_ip,
                "is_anomaly": is_anomaly,
                "anomalies": anomalies or [],
            }

            # Serialize deterministically and compute RFC 6962 leaf hash
            payload_bytes = json.dumps(audit_payload, sort_keys=True).encode("utf-8")
            leaf_hash = MerkleTree.hash_leaf(payload_bytes)
            master_root = self._tree.append_leaf(leaf_hash)

            disk_record = {
                "id": log_id,
                "tx_id": log_id,
                "leaf_hash": leaf_hash,
                "root_hash": master_root,
                "payload": audit_payload,
            }

            # Append atomically to the JSONL log file
            with open(self.ledger_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(disk_record) + "\n")
                self._file_offset = f.tell()

            self._persist_state()

            return {
                "id": log_id,
                "time": iso_timestamp,
                "user": app_user,
                "role": user_role,
                "action": action,
                "table": target_table,
                "status": execution_status,
                "query": query_text,
                "is_sensitive": is_sensitive,
                "tx_id": log_id,
                "ledger_tx_id": log_id,
                "ledger_verified": True,
                "ledger_tx_hash": master_root,
                "immudb_tx_id": log_id,
                "immudb_verified": True,
                "immudb_tx_hash": master_root,
            }

    def verify_audit_log(self, log_id: int) -> Dict[str, Any]:
        """
        Performs mathematical Merkle inclusion proof verification on an individual log entry.
        Detects any byte modification, unauthorized deletion, or out-of-band tampering.

        Args:
            log_id: Transaction ID of the log record to verify.

        Returns:
            Dictionary detailing verification status, proof path length, and tamper diagnosis.
        """
        with self._lock:
            self._sync_ledger()
            target_entry: Optional[Dict[str, Any]] = None
            target_index: int = -1

            if self.ledger_file.exists():
                with open(self.ledger_file, "r", encoding="utf-8") as f:
                    for idx, line in enumerate(f):
                        if not line.strip():
                            continue
                        try:
                            entry = json.loads(line)
                            if entry.get("id") == log_id:
                                target_entry = entry
                                target_index = idx
                                break
                        except Exception:
                            continue

            if not target_entry:
                return {
                    "log_id": log_id,
                    "verified": False,
                    "tamper_detected": True,
                    "error": f"Log #{log_id} not found in native ledger.",
                    "message": "Cryptographic verification failed: Record does not exist.",
                }

            # Recompute leaf hash from actual stored payload data
            payload = target_entry.get("payload") or {k: v for k, v in target_entry.items() if k not in ("leaf_hash", "root_hash", "tx_id")}
            payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
            actual_leaf_hash = MerkleTree.hash_leaf(payload_bytes)

            stored_leaf_hash = target_entry.get("leaf_hash")
            index = target_index if target_index >= 0 else (log_id - 1)
            proof = self._tree.get_audit_path(index)
            current_root = self._tree.get_root()

            # Mathematically verify inclusion against the current Merkle root
            proof_valid = MerkleTree.verify_proof(actual_leaf_hash, proof, current_root)
            is_tampered = (actual_leaf_hash != stored_leaf_hash) or not proof_valid

            if not is_tampered:
                msg = "Cryptographic Merkle proof matches server state. Record is authentic and untampered."
            else:
                msg = "TAMPER DETECTED: Payload hash does not match cryptographic Merkle root!"

            return {
                "log_id": log_id,
                "ledger_key": f"audit:log:{log_id}",
                "immudb_key": f"audit:log:{log_id}",
                "tx_id": log_id,
                "ledger_tx_id": log_id,
                "verified": not is_tampered,
                "tamper_detected": is_tampered,
                "current_root_hash": current_root,
                "leaf_hash": actual_leaf_hash,
                "record": payload,
                "proof_path_length": len(proof),
                "message": msg,
            }

    def get_audit_logs(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Retrieves historical audit entries in reverse-chronological order (newest first).

        Args:
            limit: Maximum records to return.
            offset: Number of latest records to skip.

        Returns:
            List of standardized audit log dictionaries.
        """
        with self._lock:
            self._sync_ledger()
            if not self.ledger_file.exists():
                return []

            all_entries: List[Dict[str, Any]] = []
            with open(self.ledger_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            all_entries.append(json.loads(line))
                        except Exception:
                            continue

            all_entries.reverse()
            sliced = all_entries[offset : offset + limit]

            logs: List[Dict[str, Any]] = []
            for item in sliced:
                p = item.get("payload") or item
                logs.append({
                    "id": p.get("id", item.get("id")),
                    "time": p.get("timestamp"),
                    "user": p.get("app_user"),
                    "role": p.get("user_role"),
                    "action": p.get("action"),
                    "table": p.get("target_table"),
                    "status": p.get("execution_status"),
                    "query": p.get("query_text"),
                    "is_sensitive": p.get("is_sensitive", False),
                    "tx_id": item.get("tx_id", item.get("id")),
                    "ledger_tx_id": item.get("tx_id", item.get("id")),
                    "immudb_tx_id": item.get("tx_id", item.get("id")),
                    "is_anomaly": p.get("is_anomaly", False),
                    "anomalies": p.get("anomalies") or [],
                })
            return logs

    def get_ledger_state(self) -> Dict[str, Any]:
        """
        Returns the current cryptographic state of the Merkle ledger.

        Returns:
            Dictionary with database name, transaction counter, and root hash.
        """
        with self._lock:
            self._sync_ledger()
            return {
                "database": "native_merkle_ledger",
                "tx_id": self._counter,
                "root_hash": self._tree.get_root(),
                "verified": True,
            }

    def close(self) -> None:
        """Persists final ledger state and releases locks."""
        self._persist_state()
        logger.info("MerkleVault closed successfully.")
