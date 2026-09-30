"""
VaultClient - Backward Compatibility Facade
Wraps the new scalable VaultEngine architecture while preserving the original v1 interface.
All operations now pass through RBAC and are recorded in the tamper-proof immudb ledger.
"""

from typing import Any, List, Optional, Tuple
from src.vault_db.core.engine import VaultEngine
from src.vault_db.core.rbac import AccessDeniedError


class VaultClient:
    """Compatibility client providing identical methods to v1, powered by VaultEngine v2."""

    def __init__(self, *args, **kwargs):
        self.engine = VaultEngine()
        self.last_rows_affected = 0
        self.last_columns = []
        self.last_immudb_tx_id = None
        self.last_immudb_verified = None

    def get_role(self, email: str) -> str:
        return self.engine.get_user_role(email)

    def execute(self, query: str, params: Optional[Tuple[Any, ...]] = None, app_user: str = "alice@bank.com"):
        res = self.engine.execute(query=query, params=params, app_user=app_user)
        self.last_rows_affected = res.get("rows_affected", 0)
        self.last_columns = res.get("columns", [])
        self.last_immudb_tx_id = res.get("immudb_tx_id")
        self.last_immudb_verified = res.get("immudb_verified")
        return res.get("results", [])

    def get_audit_logs(self, limit: int = 10):
        # Fetch from immudb with PostgreSQL fallback
        raw_logs = self.engine.get_audit_logs(limit=limit, source="immudb")
        # Return format compatible with legacy tuple expectations:
        # (log_id, time, app_user, user_role, action, target_table, execution_status, query_text)
        tuples = []
        for l in raw_logs:
            tuples.append((
                l.get("id"),
                l.get("time"),
                l.get("user"),
                l.get("role"),
                l.get("action"),
                l.get("table"),
                l.get("status"),
                l.get("query"),
            ))
        return tuples

    def verify_audit_log(self, log_id: int):
        return self.engine.verify_audit_log(log_id)

    def close(self):
        self.engine.close()