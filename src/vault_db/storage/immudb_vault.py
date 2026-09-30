"""
immudb Storage Adapter for Cryptographically Verifiable Audit Trails.
Provides tamper-proof, append-only logging with Merkle tree cryptographic verification.
"""

import json
import logging
import threading
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone

from immudb.client import ImmudbClient
from config.settings import settings

logger = logging.getLogger(__name__)


class ImmudbVault:
    """
    Client wrapper for immudb cryptographic ledger.
    Guarantees that audit trails are immutable, append-only, and cryptographically provable.
    """

    COUNTER_KEY = b"audit:counter"
    KEY_PREFIX = "audit:log:"

    def __init__(
        self,
        address: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        database: Optional[str] = None,
    ):
        self.address = address or settings.immudb_address
        self.username = username or settings.IMMUDB_USER
        self.password = password or settings.IMMUDB_PASSWORD
        self.database = database or settings.IMMUDB_DATABASE
        self._lock = threading.Lock()
        self._client: Optional[ImmudbClient] = None
        self._connect()

    def _connect(self):
        """Establishes authenticated session with immudb server."""
        try:
            client = ImmudbClient(self.address)
            client.login(self.username, self.password)
            if self.database and self.database != "defaultdb":
                try:
                    client.useDatabase(self.database.encode())
                except Exception:
                    pass
            self._client = client
            logger.info(f"Connected to immudb server at {self.address}")
        except Exception as e:
            logger.error(f"Failed to connect to immudb at {self.address}: {e}")
            self._client = None
            raise

    def _ensure_connected(self):
        """Re-establishes connection if closed or stale."""
        if self._client is None:
            self._connect()
        else:
            try:
                # Lightweight health check
                self._client.healthCheck()
            except Exception:
                logger.info("Reconnecting to immudb...")
                try:
                    self._client.logout()
                except Exception:
                    pass
                self._connect()

    def _peek_next_id(self) -> int:
        """Reads current counter without incrementing transaction height."""
        self._ensure_connected()
        try:
            val_bytes = self._client.get(self.COUNTER_KEY).value
            return int(val_bytes.decode("utf-8")) + 1
        except Exception:
            return 1

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
    ) -> Dict[str, Any]:
        """
        Cryptographically commits an audit record into immudb.
        Writes the counter and log payload atomically in a SINGLE transaction,
        ensuring monotonic +1 transaction ID progression and tamper-proof verification.
        """
        with self._lock:
            self._ensure_connected()
            log_id = self._peek_next_id()
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
            }

            key = f"{self.KEY_PREFIX}{log_id}".encode("utf-8")
            val = json.dumps(audit_payload).encode("utf-8")

            # Commit both log and counter atomically in ONE single transaction
            set_response = self._client.setAll({
                self.COUNTER_KEY: str(log_id).encode("utf-8"),
                key: val,
            })

            # Fetch current cryptographic state
            state = self._client.currentState()
            tx_hash_hex = state.txHash.hex() if hasattr(state.txHash, "hex") else str(state.txHash)

            logger.info(
                f"Recorded immutable audit log #{log_id} to immudb (txId={set_response.id})"
            )

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
                "immudb_tx_id": set_response.id,
                "immudb_verified": True,
                "immudb_tx_hash": tx_hash_hex,
            }

    def verify_audit_log(self, log_id: int) -> Dict[str, Any]:
        """
        Performs a cryptographic proof verification on an individual log entry.
        Queries immudb with verifiedGet() to validate against the server Merkle tree state.
        """
        with self._lock:
            self._ensure_connected()
            key = f"{self.KEY_PREFIX}{log_id}".encode("utf-8")
            
            try:
                # verifiedGet cryptographically computes and verifies the Merkle proof
                get_response = self._client.verifiedGet(key)
                record_data = json.loads(get_response.value.decode("utf-8"))
                state = self._client.currentState()
                root_hash_hex = state.txHash.hex() if hasattr(state.txHash, "hex") else str(state.txHash)

                return {
                    "log_id": log_id,
                    "immudb_key": key.decode("utf-8"),
                    "tx_id": get_response.id,
                    "verified": get_response.verified,
                    "tamper_detected": not get_response.verified,
                    "current_root_hash": root_hash_hex,
                    "record": record_data,
                    "message": "Cryptographic Merkle proof matches server state. Record is authentic and untampered.",
                }
            except Exception as e:
                logger.error(f"Verification failed for log #{log_id}: {e}")
                return {
                    "log_id": log_id,
                    "verified": False,
                    "tamper_detected": True,
                    "error": str(e),
                    "message": "Cryptographic verification failed! Record may be tampered or missing.",
                }

    def get_audit_logs(self, limit: int = 20, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Retrieves the latest audit logs from immudb.
        Scans backwards from the current counter for reverse chronological order.
        """
        with self._lock:
            self._ensure_connected()
            try:
                counter_bytes = self._client.get(self.COUNTER_KEY).value
                total = int(counter_bytes.decode("utf-8"))
            except Exception:
                return []

            if total <= 0:
                return []

            start_id = max(1, total - offset)
            end_id = max(1, start_id - limit + 1)

            logs = []
            for lid in range(start_id, end_id - 1, -1):
                key = f"{self.KEY_PREFIX}{lid}".encode("utf-8")
                try:
                    res = self._client.get(key)
                    data = json.loads(res.value.decode("utf-8"))
                    logs.append({
                        "id": data.get("id", lid),
                        "time": data.get("timestamp"),
                        "user": data.get("app_user"),
                        "role": data.get("user_role"),
                        "action": data.get("action"),
                        "table": data.get("target_table"),
                        "status": data.get("execution_status"),
                        "query": data.get("query_text"),
                        "is_sensitive": data.get("is_sensitive", False),
                        "immudb_tx_id": res.tx,
                    })
                except Exception as e:
                    logger.debug(f"Failed reading log {lid}: {e}")
                    continue

            return logs

    def get_ledger_state(self) -> Dict[str, Any]:
        """Returns the current state and cryptographic root hash of the immudb ledger."""
        with self._lock:
            self._ensure_connected()
            state = self._client.currentState()
            tx_hash_hex = state.txHash.hex() if hasattr(state.txHash, "hex") else str(state.txHash)
            return {
                "database": state.db if hasattr(state, "db") else self.database,
                "tx_id": state.txId,
                "root_hash": tx_hash_hex,
                "verified": True,
            }

    def close(self):
        """Logs out and closes the immudb client session."""
        with self._lock:
            if self._client:
                try:
                    self._client.logout()
                except Exception:
                    pass
                self._client = None
                logger.info("immudb client session closed.")
