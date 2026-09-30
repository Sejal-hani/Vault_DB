"""
VaultEngine - Core Middleware Orchestrator
Intercepts SQL operations, verifies RBAC permissions, routes business queries to PostgreSQL,
and cryptographically records all audit trails into immudb.
"""

import time
import logging
from typing import Any, Dict, List, Optional, Tuple

from src.vault_db.core.rbac import RBACManager, AccessDeniedError, QueryExecutionError
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
        
        # Resolve human identity & role
        try:
            user_role = self.get_user_role(app_user)
        except Exception:
            user_role = "unknown"

        # Analyze SQL query safely
        try:
            analysis = SQLParser.analyze(query)
            target_str = ", ".join(analysis.tables) if analysis.tables else "unknown"
        except Exception:
            analysis = QueryAnalysis(raw_query=query, action="UNKNOWN")
            target_str = "unknown"

        # 1. RBAC Policy Enforcement
        is_allowed, denial_reason = self.rbac.check_authorization(
            role=user_role,
            action=analysis.action,
            tables=analysis.tables,
        )

        if not is_allowed:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            # Cryptographically seal security violation into immudb ledger
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
            try:
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
            except Exception as pe_err:
                logger.warning(f"Could not write redundant denial log to PostgreSQL: {pe_err}")

            raise AccessDeniedError(f"Access Denied: {denial_reason}", immudb_record=immudb_record)

        # 2. Execution on Business Database (PostgreSQL)
        try:
            results, columns, rows_affected = self.postgres.execute_query(query, params)
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            # Cryptographically record failed/bad query into immudb ledger
            immudb_record = self.immudb.append_audit_log(
                app_user=app_user,
                user_role=user_role,
                action=analysis.action,
                target_table=target_str,
                query_text=query,
                execution_status="ERROR",
                execution_time_ms=elapsed_ms,
                is_sensitive=analysis.is_sensitive,
                sensitive_fields=analysis.sensitive_fields_found,
                client_ip=client_ip,
            )
            try:
                self.postgres.write_audit_log(
                    app_user=app_user,
                    user_role=user_role,
                    action=analysis.action,
                    target_table=target_str,
                    query_text=query,
                    execution_status="ERROR",
                    immudb_tx_id=immudb_record.get("immudb_tx_id"),
                    immudb_tx_hash=immudb_record.get("immudb_tx_hash"),
                )
            except Exception as pe_err:
                logger.warning(f"Could not write redundant error log to PostgreSQL: {pe_err}")

            raise QueryExecutionError(str(e), immudb_record=immudb_record)

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # 3. Cryptographically append successful audit record to immudb
        immudb_record = self.immudb.append_audit_log(
            app_user=app_user,
            user_role=user_role,
            action=analysis.action,
            target_table=target_str,
            query_text=query,
            execution_status="SUCCESS",
            execution_time_ms=elapsed_ms,
            is_sensitive=analysis.is_sensitive,
            sensitive_fields=analysis.sensitive_fields_found,
            client_ip=client_ip,
        )

        # Redundant copy in PostgreSQL
        try:
            self.postgres.write_audit_log(
                app_user=app_user,
                user_role=user_role,
                action=analysis.action,
                target_table=target_str,
                query_text=query,
                execution_status="SUCCESS",
                immudb_tx_id=immudb_record.get("immudb_tx_id"),
                immudb_tx_hash=immudb_record.get("immudb_tx_hash"),
            )
        except Exception as pe_err:
            logger.warning(f"Could not write redundant success log to PostgreSQL: {pe_err}")

        return {
            "status": "SUCCESS",
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
