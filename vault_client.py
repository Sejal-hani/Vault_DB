"""
VaultDB - Query Middleware Client
Intercepts SQL queries, extracts metadata, executes against PostgreSQL via psycopg,
and records immutable audit entries into vault_audit.audit_logs.
"""
import re
import psycopg
from typing import Any, List, Optional, Tuple

# Sensitive column names to monitor for compliance alerts
SENSITIVE_KEYWORDS = {"ssn", "credit_card", "password", "secret", "cvv"}


# ============================================================================
# 1. SQL QUERY PARSER HELPERS
# ============================================================================

def extract_action(query: str) -> str:
    """Extracts SQL operation: SELECT, INSERT, UPDATE, DELETE."""
    match = re.match(r"^\s*([A-Za-z]+)", query.strip())
    if match:
        action = match.group(1).upper()
        if action in {"SELECT", "INSERT", "UPDATE", "DELETE"}:
            return action
    return "UNKNOWN"


def extract_table(query: str) -> str:
    """Extracts target table name (e.g. app_data.customers -> customers)."""
    query_clean = query.strip()
    action = extract_action(query_clean)

    pattern = None
    if action in {"SELECT", "DELETE"}:
        pattern = r"\bFROM\s+(?:[A-Za-z0-9_]+\.)?([A-Za-z0-9_]+)"
    elif action == "INSERT":
        pattern = r"\bINTO\s+(?:[A-Za-z0-9_]+\.)?([A-Za-z0-9_]+)"
    elif action == "UPDATE":
        pattern = r"\bUPDATE\s+(?:[A-Za-z0-9_]+\.)?([A-Za-z0-9_]+)"

    if pattern:
        match = re.search(pattern, query_clean, re.IGNORECASE)
        if match:
            return match.group(1).lower()

    return "unknown"


def is_sensitive_query(query: str) -> bool:
    """Returns True if the query touches any sensitive columns."""
    query_lower = query.lower()
    for kw in SENSITIVE_KEYWORDS:
        if re.search(rf"\b{re.escape(kw)}\b", query_lower):
            return True
    return False


# ============================================================================
# 2. CORE VAULTDB MIDDLEWARE CLIENT
# ============================================================================

class VaultClient:
    """
    Database middleware client wrapping psycopg.
    All executed queries are automatically audited to vault_audit.audit_logs.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5432,
        user: str = "postgres",
        password: Optional[str] = None,
        dbname: str = "postgres"
    ):
        # Establish direct connection to PostgreSQL
        self.conn = psycopg.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            dbname=dbname,
            autocommit=True
        )

    def execute(
        self,
        query: str,
        params: Optional[Tuple[Any, ...]] = None,
        app_user: str = "anonymous",
        user_role: str = "reader"
    ) -> List[Tuple[Any, ...]]:
        """
        Executes an SQL query through the middleware:
        1. Parses action, target table, and sensitivity flag.
        2. Dispatches query to PostgreSQL.
        3. Writes audit record to vault_audit.audit_logs.
        4. Returns result rows (if any).
        """
        action = extract_action(query)
        target_table = extract_table(query)
        is_sensitive = is_sensitive_query(query)
        rows_affected = 0
        execution_status = "SUCCESS"
        error_message = None
        results = []

        try:
            with self.conn.cursor() as cur:
                cur.execute(query, params)
                if cur.description is not None:
                    # Query returned data (SELECT)
                    results = cur.fetchall()
                    rows_affected = len(results)
                else:
                    # Data modification query (INSERT, UPDATE, DELETE)
                    rows_affected = cur.rowcount if cur.rowcount != -1 else 0
            return results

        except Exception as e:
            execution_status = "ERROR"
            error_message = str(e)
            raise e

        finally:
            # Audit log is ALWAYS recorded, even if query failed
            self._write_audit_log(
                app_user=app_user,
                user_role=user_role,
                action=action,
                target_table=target_table,
                query_text=query,
                rows_affected=rows_affected,
                is_sensitive=is_sensitive,
                execution_status=execution_status,
                error_message=error_message
            )

    def _write_audit_log(
        self,
        app_user: str,
        user_role: str,
        action: str,
        target_table: str,
        query_text: str,
        rows_affected: int,
        is_sensitive: bool,
        execution_status: str,
        error_message: Optional[str]
    ) -> None:
        """Internal helper to insert audit trail into vault_audit.audit_logs."""
        audit_sql = """
            INSERT INTO vault_audit.audit_logs (
                app_user, user_role, action, target_table,
                query_text, rows_affected, is_sensitive,
                execution_status, error_message
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
        """
        try:
            with self.conn.cursor() as cur:
                cur.execute(
                    audit_sql,
                    (
                        app_user, user_role, action, target_table,
                        query_text, rows_affected, is_sensitive,
                        execution_status, error_message
                    )
                )
        except Exception as log_err:
            # Print error if logging fails (fail-safe)
            print(f"[CRITICAL] VaultDB failed to write audit log: {log_err}")

    def get_audit_logs(self, limit: int = 10) -> List[Tuple[Any, ...]]:
        """Convenience method to retrieve the latest audit records."""
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT log_id, logged_at, app_user, user_role, action,
                       target_table, is_sensitive, execution_status, rows_affected
                FROM vault_audit.audit_logs
                ORDER BY log_id DESC
                LIMIT %s;
            """, (limit,))
            return cur.fetchall()

    def close(self) -> None:
        """Closes the underlying database connection."""
        if self.conn and not self.conn.closed:
            self.conn.close()

