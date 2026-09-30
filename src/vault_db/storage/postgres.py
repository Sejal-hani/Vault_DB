"""
PostgreSQL Storage Adapter with Connection Pooling
Provides high-performance, concurrent access to relational business tables.
"""

import logging
from typing import Any, List, Optional, Tuple
from psycopg_pool import ConnectionPool
from config.settings import settings

logger = logging.getLogger(__name__)


class PostgresStorage:
    """Manages pooled connections to PostgreSQL for business queries and user roles."""

    def __init__(
        self,
        conninfo: Optional[str] = None,
        min_size: int = settings.POSTGRES_POOL_MIN,
        max_size: int = settings.POSTGRES_POOL_MAX,
    ):
        self.conninfo = conninfo or settings.postgres_conninfo
        self.min_size = min_size
        self.max_size = max_size
        self._pool: Optional[ConnectionPool] = None
        self._init_pool()

    def _init_pool(self):
        try:
            self._pool = ConnectionPool(
                conninfo=self.conninfo,
                min_size=self.min_size,
                max_size=self.max_size,
                open=True,
                kwargs={"autocommit": True}
            )
            self._pool.wait()
            logger.info("PostgreSQL ConnectionPool established.")
        except Exception as e:
            logger.error(f"Failed to initialize PostgreSQL ConnectionPool: {e}")
            raise

    def get_user_role(self, email: str) -> str:
        """Looks up user role from app_data.users table."""
        if not self._pool:
            return "customer"

        sql = "SELECT role FROM app_data.users WHERE email = %s;"
        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, (email,))
                    row = cur.fetchone()
                    if row:
                        return row[0]
        except Exception as e:
            logger.warning(f"Error fetching role for {email}: {e}")
        return "customer"

    def execute_query(
        self, query: str, params: Optional[Tuple[Any, ...]] = None
    ) -> Tuple[List[Any], List[str], int]:
        """
        Executes business query on PostgreSQL.
        Returns: (results_list, column_names_list, rows_affected)
        """
        if not self._pool:
            raise RuntimeError("PostgreSQL ConnectionPool is not available.")

        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query, params)
                columns: List[str] = []
                results: List[Any] = []
                if cur.description is not None:
                    columns = [desc[0] for desc in cur.description]
                    results = cur.fetchall()
                    rows_affected = len(results)
                else:
                    rows_affected = cur.rowcount if cur.rowcount != -1 else 0
                return results, columns, rows_affected

    def write_audit_log(
        self,
        app_user: str,
        user_role: str,
        action: str,
        target_table: str,
        query_text: str,
        execution_status: str,
        immudb_tx_id: Optional[int] = None,
        immudb_tx_hash: Optional[str] = None
    ) -> Optional[int]:
        """Writes audit entry to PostgreSQL vault_audit.audit_logs for relational redundancy."""
        if not self._pool:
            return None

        sql = """
            INSERT INTO vault_audit.audit_logs 
            (app_user, user_role, action, target_table, query_text, execution_status)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING log_id;
        """
        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, (app_user, user_role, action, target_table, query_text, execution_status))
                    row = cur.fetchone()
                    return row[0] if row else None
        except Exception as e:
            logger.warning(f"Failed writing audit log to PostgreSQL: {e}")
            return None

    def get_audit_logs(self, limit: int = 20) -> List[dict]:
        """Fetches latest audit logs from PostgreSQL table."""
        if not self._pool:
            return []

        sql = """
            SELECT log_id, logged_at, app_user, user_role, action, target_table, execution_status, query_text
            FROM vault_audit.audit_logs
            ORDER BY log_id DESC
            LIMIT %s;
        """
        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, (limit,))
                    rows = cur.fetchall()
                    logs = []
                    for r in rows:
                        logs.append({
                            "id": r[0],
                            "time": r[1].isoformat() if hasattr(r[1], 'isoformat') else str(r[1]),
                            "user": r[2],
                            "role": r[3],
                            "action": r[4],
                            "table": r[5],
                            "status": r[6],
                            "query": r[7] if len(r) > 7 else ""
                        })
                    return logs
        except Exception as e:
            logger.error(f"Error reading audit logs from PostgreSQL: {e}")
            return []

    def close(self):
        """Closes the connection pool."""
        if self._pool:
            self._pool.close()
            self._pool = None
            logger.info("PostgreSQL ConnectionPool closed.")
