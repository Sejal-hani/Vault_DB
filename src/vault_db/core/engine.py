"""
VaultEngine - Core Middleware Orchestrator
Intercepts SQL operations, verifies RBAC permissions, routes business queries to PostgreSQL,
and cryptographically records all audit trails into immudb.
"""

import re
import time
import logging
from typing import Any, Dict, List, Optional, Tuple

from src.vault_db.core.rbac import RBACManager, AccessDeniedError, QueryExecutionError
from src.vault_db.core.parser import SQLParser, QueryAnalysis
from src.vault_db.storage.postgres import PostgresStorage
from src.vault_db.storage.immudb_vault import ImmudbVault
from src.vault_db.core.masking import mask_tabular_results, mask_query_text
from src.vault_db.core.rls import apply_row_level_security
from src.vault_db.core.anomaly import AnomalyDetector
from src.vault_db.core.alerts import AlertDispatcher
from src.vault_db.core.approval import ApprovalManager

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
        approval_manager: Optional[ApprovalManager] = None,
    ):
        self.postgres = postgres_storage or PostgresStorage()
        self.immudb = immudb_vault or ImmudbVault()
        self.rbac = rbac_manager or RBACManager()
        self.approvals = approval_manager or ApprovalManager(self.postgres, self.immudb)

    def get_user_role(self, app_user: str) -> str:
        """Resolves user role, checking time-bounded approved elevations (24h) first."""
        elevated = self.approvals.check_active_elevation(app_user)
        if elevated:
            return elevated
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

        # Sanitize query string for immutable logging (V2: Mask in logs AND in results)
        logged_query = mask_query_text(query)

        # 1. Multi-statement / stacked SQL injection check (prohibited for all personas)
        if analysis.action == "MULTI_STATEMENT":
            elapsed_ms = (time.perf_counter() - start_time) * 1000

            # Evaluate genuine security anomalies on policy denial
            denial_anomalies = AnomalyDetector.evaluate(
                query=query,
                rows_affected=0,
                execution_status="DENIED",
                user_role=user_role,
                app_user=app_user,
                action="MULTI_STATEMENT",
                target_table=target_str,
                is_sensitive=analysis.is_sensitive,
            )

            immudb_record = self.immudb.append_audit_log(
                app_user=app_user,
                user_role=user_role,
                action="MULTI_STATEMENT",
                target_table=target_str,
                query_text=logged_query,
                execution_status="DENIED",
                execution_time_ms=elapsed_ms,
                is_sensitive=analysis.is_sensitive,
                sensitive_fields=analysis.sensitive_fields_found,
                client_ip=client_ip,
                is_anomaly=bool(denial_anomalies),
                anomalies=[a["name"] for a in denial_anomalies],
            )
            try:
                self.postgres.write_audit_log(
                    app_user=app_user,
                    user_role=user_role,
                    action="MULTI_STATEMENT",
                    target_table=target_str,
                    query_text=logged_query,
                    execution_status="DENIED",
                    immudb_log_id=immudb_record.get("id"),
                    immudb_tx_id=immudb_record.get("immudb_tx_id"),
                    immudb_tx_hash=immudb_record.get("immudb_tx_hash"),
                    is_sensitive=analysis.is_sensitive,
                )
            except Exception as pe_err:
                logger.warning(f"Could not write redundant denial log to PostgreSQL: {pe_err}")

            if denial_anomalies:
                try:
                    AlertDispatcher.dispatch_anomaly_alert(
                        app_user=app_user,
                        user_role=user_role,
                        anomalies=denial_anomalies,
                        query=logged_query,
                        rows_affected=0,
                        execution_status="DENIED",
                        client_ip=client_ip,
                        immudb_log_id=immudb_record.get("id"),
                        target_table=target_str,
                    )
                except Exception:
                    pass

            raise AccessDeniedError(
                "Access Denied: Multi-statement execution / stacked SQL injection is prohibited by security policy.",
                immudb_record=immudb_record
            )

        # 2. RBAC Policy Enforcement on existing real database tables
        existing_relations = self.postgres.get_existing_relations()
        real_tables = [t for t in analysis.tables if t.lower() in existing_relations]

        # Only evaluate table-level RBAC if the query targets real database tables.
        # If the query references only non-existent tables (e.g. typos like 'transacti' or 'u'),
        # we skip the RBAC access denial so that PostgreSQL executes it and returns a genuine
        # database error ('relation ... does not exist') instead of an access violation.
        if real_tables or not analysis.tables:
            is_allowed, denial_reason = self.rbac.check_authorization(
                role=user_role,
                action=analysis.action,
                tables=real_tables,
            )

            if not is_allowed:
                elapsed_ms = (time.perf_counter() - start_time) * 1000

                # Evaluate genuine security anomalies on policy denial
                denial_anomalies = AnomalyDetector.evaluate(
                    query=query,
                    rows_affected=0,
                    execution_status="DENIED",
                    user_role=user_role,
                    app_user=app_user,
                    action=analysis.action,
                    target_table=target_str,
                    is_sensitive=analysis.is_sensitive,
                )

                # Cryptographically seal security violation into immudb ledger
                immudb_record = self.immudb.append_audit_log(
                    app_user=app_user,
                    user_role=user_role,
                    action=analysis.action,
                    target_table=target_str,
                    query_text=logged_query,
                    execution_status="DENIED",
                    execution_time_ms=elapsed_ms,
                    is_sensitive=analysis.is_sensitive,
                    sensitive_fields=analysis.sensitive_fields_found,
                    client_ip=client_ip,
                    is_anomaly=bool(denial_anomalies),
                    anomalies=[a["name"] for a in denial_anomalies],
                )
                # Redundant copy in PostgreSQL
                try:
                    self.postgres.write_audit_log(
                        app_user=app_user,
                        user_role=user_role,
                        action=analysis.action,
                        target_table=target_str,
                        query_text=logged_query,
                        execution_status="DENIED",
                        immudb_log_id=immudb_record.get("id"),
                        immudb_tx_id=immudb_record.get("immudb_tx_id"),
                        immudb_tx_hash=immudb_record.get("immudb_tx_hash"),
                        is_sensitive=analysis.is_sensitive,
                    )
                except Exception as pe_err:
                    logger.warning(f"Could not write redundant denial log to PostgreSQL: {pe_err}")

                if denial_anomalies:
                    try:
                        AlertDispatcher.dispatch_anomaly_alert(
                            app_user=app_user,
                            user_role=user_role,
                            anomalies=denial_anomalies,
                            query=logged_query,
                            rows_affected=0,
                            execution_status="DENIED",
                            client_ip=client_ip,
                            immudb_log_id=immudb_record.get("id"),
                            target_table=target_str,
                        )
                    except Exception:
                        pass

                raise AccessDeniedError(f"Access Denied: {denial_reason}", immudb_record=immudb_record)

        # 1.5. Customer Tenant Isolation Enforcement
        if user_role.lower() == "customer":
            clean_email = app_user.strip().lower()
            acc_matches = re.findall(r"\bACC-\d+\b", query, re.IGNORECASE)
            id_matches = re.findall(r"\baccount_id\s*=\s*(\d+)", query, re.IGNORECASE)
            if acc_matches or id_matches:
                try:
                    user_accs = self.postgres.execute_query(
                        "SELECT account_number, id FROM app_data.accounts WHERE user_id = (SELECT id FROM app_data.users WHERE email = %s);",
                        (clean_email,)
                    )[0]
                except Exception:
                    user_accs = []
                own_acc_nums = {str(r[0]).upper() for r in user_accs if r[0]}
                own_acc_ids = {str(r[1]) for r in user_accs if r[1] is not None}

                violating_acc = None
                for a_m in acc_matches:
                    if a_m.upper() not in own_acc_nums:
                        violating_acc = a_m.upper()
                        break

                violating_id = None
                if not violating_acc:
                    for i_m in id_matches:
                        if i_m not in own_acc_ids:
                            violating_id = i_m
                            break

                if violating_acc or violating_id:
                    detail = f"account '{violating_acc}'" if violating_acc else f"account #{violating_id}"
                    denial_reason = f"Cross-tenant isolation violation: Customer '{clean_email}' is not permitted to query {detail} belonging to another client."
                    elapsed_ms = (time.perf_counter() - start_time) * 1000
                    logged_query = mask_query_text(query)
                    target_str = ",".join(analysis.tables) if analysis.tables else "accounts"

                    # Evaluate genuine security anomalies on cross-tenant violation
                    denial_anomalies = AnomalyDetector.evaluate(
                        query=query,
                        rows_affected=0,
                        execution_status="DENIED",
                        user_role=user_role,
                        app_user=app_user,
                        action=analysis.action,
                        target_table=target_str,
                        is_sensitive=analysis.is_sensitive,
                    )

                    immudb_record = self.immudb.append_audit_log(
                        app_user=app_user,
                        user_role=user_role,
                        action=analysis.action,
                        target_table=target_str,
                        query_text=logged_query,
                        execution_status="DENIED",
                        execution_time_ms=elapsed_ms,
                        is_sensitive=analysis.is_sensitive,
                        sensitive_fields=analysis.sensitive_fields_found,
                        client_ip=client_ip,
                        is_anomaly=bool(denial_anomalies),
                        anomalies=[a["name"] for a in denial_anomalies],
                    )
                    try:
                        self.postgres.write_audit_log(
                            app_user=app_user,
                            user_role=user_role,
                            action=analysis.action,
                            target_table=target_str,
                            query_text=logged_query,
                            execution_status="DENIED",
                            immudb_log_id=immudb_record.get("id"),
                            immudb_tx_id=immudb_record.get("immudb_tx_id"),
                            immudb_tx_hash=immudb_record.get("immudb_tx_hash"),
                            is_sensitive=analysis.is_sensitive,
                        )
                    except Exception as pe_err:
                        logger.warning(f"Could not write redundant denial log to PostgreSQL: {pe_err}")

                    if denial_anomalies:
                        try:
                            AlertDispatcher.dispatch_anomaly_alert(
                                app_user=app_user,
                                user_role=user_role,
                                anomalies=denial_anomalies,
                                query=logged_query,
                                rows_affected=0,
                                execution_status="DENIED",
                                client_ip=client_ip,
                                immudb_log_id=immudb_record.get("id"),
                                target_table=target_str,
                            )
                        except Exception:
                            pass

                    raise AccessDeniedError(f"Access Denied: {denial_reason}", immudb_record=immudb_record)

        # 2. Row-Level Security (RLS) Enforcement
        exec_query, is_scoped = apply_row_level_security(query, user_role, app_user)

        # 3. Execution on Business Database (PostgreSQL)
        try:
            results, columns, rows_affected = self.postgres.execute_query(exec_query, params)
        except Exception as e:
            raise QueryExecutionError(str(e))

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # 4. Dynamic Data Masking (V2 Scope)
        masked_results, is_masked, masked_cols = mask_tabular_results(columns, results, user_role)

        sensitive_in_cols = [c for c in columns if any(s in c.lower() for s in ("ssn", "password", "secret", "api_key", "token"))]
        is_sensitive_effective = bool(analysis.is_sensitive or is_masked or masked_cols or sensitive_in_cols)
        sensitive_fields_effective = sorted(list(set(analysis.sensitive_fields_found + masked_cols + sensitive_in_cols)))

        # Mask sensitive query constants in logs (V2 Scope: 'Mask in logs AND in results')
        logged_query = mask_query_text(query)

        # 5. Anomaly Detection (V2 Scope: Evaluates against genuine security anomaly rules)
        anomalies = AnomalyDetector.evaluate(
            query=query,
            rows_affected=rows_affected,
            execution_status="SUCCESS",
            user_role=user_role,
            app_user=app_user,
            action=analysis.action,
            target_table=target_str,
            is_sensitive=is_sensitive_effective,
        )

        # 6. Cryptographically append successful audit record to immudb
        immudb_record = self.immudb.append_audit_log(
            app_user=app_user,
            user_role=user_role,
            action=analysis.action,
            target_table=target_str,
            query_text=logged_query,
            execution_status="SUCCESS",
            execution_time_ms=elapsed_ms,
            is_sensitive=is_sensitive_effective,
            sensitive_fields=sensitive_fields_effective,
            client_ip=client_ip,
            is_anomaly=bool(anomalies),
            anomalies=[a["name"] for a in anomalies],
        )

        if anomalies:
            try:
                AlertDispatcher.dispatch_anomaly_alert(
                    app_user=app_user,
                    user_role=user_role,
                    anomalies=anomalies,
                    query=logged_query,
                    rows_affected=rows_affected,
                    execution_status="SUCCESS",
                    client_ip=client_ip,
                    immudb_log_id=immudb_record.get("id"),
                    target_table=target_str,
                )
            except Exception:
                pass

        # Redundant copy in PostgreSQL
        try:
            self.postgres.write_audit_log(
                app_user=app_user,
                user_role=user_role,
                action=analysis.action,
                target_table=target_str,
                query_text=logged_query,
                execution_status="SUCCESS",
                immudb_log_id=immudb_record.get("id"),
                immudb_tx_id=immudb_record.get("immudb_tx_id"),
                immudb_tx_hash=immudb_record.get("immudb_tx_hash"),
                is_sensitive=is_sensitive_effective,
            )
        except Exception as pe_err:
            logger.warning(f"Could not write redundant success log to PostgreSQL: {pe_err}")

        return {
            "status": "SUCCESS",
            "results": masked_results,
            "columns": columns,
            "rows_affected": rows_affected,
            "execution_time_ms": round(elapsed_ms, 2),
            "is_sensitive": is_sensitive_effective,
            "sensitive_fields": sensitive_fields_effective,
            "is_masked": is_masked,
            "masked_fields": masked_cols,
            "is_scoped": is_scoped,
            "anomalies": anomalies,
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
