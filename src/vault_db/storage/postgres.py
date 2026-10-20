"""
PostgreSQL Storage Adapter with Connection Pooling
Provides high-performance, concurrent access to relational business tables.
"""

import logging
from typing import Any, List, Optional, Tuple, Set
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
        self._cached_relations: Optional[Set[str]] = None
        self._init_pool()

    def get_existing_relations(self) -> Set[str]:
        """Returns set of all existing relation names (tables, views) in PostgreSQL."""
        if self._cached_relations is not None:
            return self._cached_relations
        try:
            results, _, _ = self.execute_query("SELECT lower(relname) FROM pg_class WHERE relkind IN ('r', 'v', 'm', 'p');")
            self._cached_relations = {r[0] for r in results}
            return self._cached_relations
        except Exception as e:
            logger.warning(f"Could not load pg_class relations: {e}")
            return {"accounts", "transactions", "users", "access_requests", "audit_logs"}

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

    def clear_role_cache(self):
        """Hook to clear external role and relation caches."""
        self._cached_relations = None

    def get_user_by_email(self, email: str) -> Optional[dict]:
        """Fetches complete user record by email."""
        if not self._pool:
            return None
        sql = "SELECT email, full_name, role, department, status, password_hash, api_key FROM app_data.users WHERE email = %s;"
        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, (email,))
                    row = cur.fetchone()
                    if row:
                        return {
                            "email": row[0],
                            "full_name": row[1],
                            "role": row[2],
                            "department": row[3],
                            "status": row[4],
                            "password_hash": row[5],
                            "api_key": row[6],
                        }
        except Exception as e:
            logger.warning(f"Error fetching user {email}: {e}")
        return None

    def get_user_by_api_key(self, api_key: str) -> Optional[dict]:
        """Fetches user record by API key."""
        if not self._pool or not api_key:
            return None
        sql = "SELECT email, full_name, role, department, status, password_hash, api_key FROM app_data.users WHERE api_key = %s;"
        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, (api_key,))
                    row = cur.fetchone()
                    if row:
                        return {
                            "email": row[0],
                            "full_name": row[1],
                            "role": row[2],
                            "department": row[3],
                            "status": row[4],
                            "password_hash": row[5],
                            "api_key": row[6],
                        }
        except Exception as e:
            logger.warning(f"Error fetching user by API key: {e}")
        return None

    def update_user_credentials(self, email: str, password_hash: str, api_key: str):
        """Updates user password hash and API key."""
        if not self._pool:
            return
        sql = "UPDATE app_data.users SET password_hash = %s, api_key = %s WHERE email = %s;"
        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, (password_hash, api_key, email))
        except Exception as e:
            logger.error(f"Error updating user credentials for {email}: {e}")

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
        immudb_log_id: Optional[int] = None,
        immudb_tx_id: Optional[int] = None,
        immudb_tx_hash: Optional[str] = None,
        is_sensitive: bool = False,
    ) -> Optional[int]:
        """Writes audit entry to PostgreSQL vault_audit.audit_logs for relational redundancy."""
        if not self._pool:
            return None

        if immudb_log_id:
            sql = """
                INSERT INTO vault_audit.audit_logs 
                (log_id, app_user, user_role, action, target_table, query_text, execution_status, immudb_tx_id, immudb_tx_hash, is_sensitive)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (log_id) DO NOTHING
                RETURNING log_id;
            """
            params = (immudb_log_id, app_user, user_role, action, target_table, query_text, execution_status, immudb_tx_id, immudb_tx_hash, is_sensitive)
        else:
            sql = """
                INSERT INTO vault_audit.audit_logs 
                (app_user, user_role, action, target_table, query_text, execution_status, immudb_tx_id, immudb_tx_hash, is_sensitive)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING log_id;
            """
            params = (app_user, user_role, action, target_table, query_text, execution_status, immudb_tx_id, immudb_tx_hash, is_sensitive)

        try:
            with self._pool.connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, params)
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
            SELECT log_id, logged_at, app_user, user_role, action, target_table, execution_status, query_text, is_sensitive, immudb_tx_id, immudb_tx_hash
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
                            "query": r[7] if len(r) > 7 else "",
                            "is_sensitive": bool(r[8]) if len(r) > 8 and r[8] is not None else False,
                            "immudb_tx_id": r[9] if len(r) > 9 else None,
                            "immudb_tx_hash": r[10] if len(r) > 10 else None,
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
