"""
VaultEngine - Core Middleware Orchestrator
Intercepts SQL operations, verifies RBAC permissions, routes business queries to PostgreSQL,
and cryptographically records all audit trails into immudb.
"""

import time
import logging
from typing import Any, Dict, List, Optional, Tuple

from src.vault_db.core.rbac import RBACManager, AccessDeniedError
from src.vault_db.core.parser import SQLParser, QueryAnalysis
from src.vault_db.storage.postgres import PostgresStorage
from src.vault_db.storage.immudb_vault import ImmudbVault

logger = logging.getLogger(__name__)


class VaultEngine:
    """
    Main VaultDB middleware engine.
    Orchestrates authentication context, RBAC validation, query execution,
    and cryptographic immutable audit logging to immudb.
    """

    def __init__(
        self,
        postgres_storage: Optional[PostgresStorage] = None,
        immudb_vault: Optional[ImmudbVault] = None,
        rbac_manager: Optional[RBACManager] = None,
    ):
        self.postgres = postgres_storage or PostgresStorage()
        self.immudb = immudb_vault or ImmudbVault()
        self.rbac = rbac_manager or RBACManager()

    def get_user_role(self, app_user: str) -> str:
        """Resolves user role from relational user registry."""
        return self.postgres.get_user_role(app_user)

    def execute(
        self,
        query: str,
        params: Optional[Tuple[Any, ...]] = None,
        app_user: str = "alice@bank.com",
        client_ip: str = "127.0.0.1",
    ) -> Dict[str, Any]:
        """
        Intercepts and processes a SQL query through compliance middleware:
        1. Analyzes SQL AST/syntax for actions, tables, and sensitive attributes.
        2. Resolves human application identity & role.
        3. Enforces RBAC permissions.
        4. Executes authorized query on PostgreSQL.
        5. Commits immutable, cryptographically verifiable audit record to immudb.
        """
        start_time = time.perf_counter()
        analysis: QueryAnalysis = SQLParser.analyze(query)
        user_role = self.get_user_role(app_user)
        target_str = ", ".join(analysis.tables) if analysis.tables else "unknown"

        # 1. RBAC Policy Enforcement
        is_allowed, denial_reason = self.rbac.check_authorization(
            role=user_role,
            action=analysis.action,
            tables=analysis.tables,
        )

        if not is_allowed:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            # Record Access Violation in immudb ledger
            immudb_record = self.immudb.append_audit_log(
                app_user=app_user,
                user_role=user_role,
                action=analysis.action,
                target_table=target_str,
                query_text=query,
                execution_status="DENIED",
                execution_time_ms=elapsed_ms,
                is_sensitive=analysis.is_sensitive,
                sensitive_fields=analysis.sensitive_fields_found,
                client_ip=client_ip,
            )
            # Redundant copy in PostgreSQL
            self.postgres.write_audit_log(
                app_user=app_user,
                user_role=user_role,
                action=analysis.action,
                target_table=target_str,
                query_text=query,
                execution_status="DENIED",
                immudb_tx_id=immudb_record.get("immudb_tx_id"),
                immudb_tx_hash=immudb_record.get("immudb_tx_hash"),
            )
            raise AccessDeniedError(f"Access Denied: {denial_reason}")

        # 2. Execution on Business Database (PostgreSQL)
        status = "SUCCESS"
        results: List[Any] = []
        columns: List[str] = []
        rows_affected: int = 0
        error_message: Optional[str] = None

        try:
            results, columns, rows_affected = self.postgres.execute_query(query, params)
        except Exception as e:
            status = "ERROR"
            error_message = str(e)
            raise
        finally:
            elapsed_ms = (time.perf_counter() - start_time) * 1000

            # 3. Cryptographically append audit record to immudb
            immudb_record = self.immudb.append_audit_log(
                app_user=app_user,
                user_role=user_role,
                action=analysis.action,
                target_table=target_str,
                query_text=query,
                execution_status=status,
                execution_time_ms=elapsed_ms,
                is_sensitive=analysis.is_sensitive,
                sensitive_fields=analysis.sensitive_fields_found,
                client_ip=client_ip,
            )

            # Redundant copy in PostgreSQL
            self.postgres.write_audit_log(
                app_user=app_user,
                user_role=user_role,
                action=analysis.action,
                target_table=target_str,
                query_text=query,
                execution_status=status,
                immudb_tx_id=immudb_record.get("immudb_tx_id"),
                immudb_tx_hash=immudb_record.get("immudb_tx_hash"),
            )

        return {
            "status": status,
            "results": results,
            "columns": columns,
            "rows_affected": rows_affected,
            "execution_time_ms": round(elapsed_ms, 2),
            "is_sensitive": analysis.is_sensitive,
            "sensitive_fields": analysis.sensitive_fields_found,
            "immudb_log_id": immudb_record.get("id"),
            "immudb_tx_id": immudb_record.get("immudb_tx_id"),
            "immudb_verified": immudb_record.get("immudb_verified"),
            "immudb_tx_hash": immudb_record.get("immudb_tx_hash"),
        }

    def get_audit_logs(self, limit: int = 20, source: str = "immudb") -> List[Dict[str, Any]]:
        """
        Fetches audit logs.
        Defaults to immudb for cryptographic tamper-proof records, with PostgreSQL as fallback.
        """
        if source == "immudb":
            logs = self.immudb.get_audit_logs(limit=limit)
            if logs:
                return logs
        return self.postgres.get_audit_logs(limit=limit)

    def verify_audit_log(self, log_id: int) -> Dict[str, Any]:
        """Validates cryptographic Merkle tree consistency proof from immudb."""
        return self.immudb.verify_audit_log(log_id)

    def get_ledger_state(self) -> Dict[str, Any]:
        """Fetches latest immudb Merkle root state."""
        return self.immudb.get_ledger_state()

    def close(self):
        """Releases all database connection pools and client sessions."""
        self.postgres.close()
        self.immudb.close()
