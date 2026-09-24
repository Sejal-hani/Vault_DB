import re
import psycopg

# 1. Security rules and roles
SENSITIVE_KEYWORDS = {"ssn", "credit_card", "password", "secret", "cvv"}
SENSITIVE_TABLES = {"customers"}
PROTECTED_TABLES = {"audit_logs"}

ROLE_PERMISSIONS = {
    "admin": {"SELECT", "INSERT", "UPDATE", "DELETE"},
    "writer": {"SELECT", "INSERT", "UPDATE"},
    "reader": {"SELECT"}
}

SQL_RESERVED = {"select", "from", "where", "join", "into", "table", "update", "set", "values", "delete"}


# 2. Query helper functions
def extract_action(query: str) -> str:
    """Finds the primary SQL action (destructive commands take precedence)."""
    q = query.strip().upper()
    for verb in ["DROP", "TRUNCATE", "ALTER", "CREATE", "DELETE", "UPDATE", "INSERT", "SELECT"]:
        if q.startswith(verb) or f" {verb} " in q or f"({verb} " in q:
            if verb in ["DROP", "TRUNCATE", "ALTER", "CREATE"]:
                return f"DDL:{verb}"
            return verb
    return "UNKNOWN"


def extract_tables(query: str) -> list:
    """Finds all table names mentioned across FROM, INTO, UPDATE, TABLE, and JOIN."""
    tables = set()
    q = query.lower()
    matches = re.finditer(r'\b(from|into|update|table|join)\s+([a-zA-Z0-9_.]+)', q)
    for m in matches:
        table_name = m.group(2).split('.')[-1]
        if table_name not in SQL_RESERVED:
            tables.add(table_name)
    return sorted(list(tables))


def is_sensitive_query(query: str, tables: list = None) -> bool:
    """Checks if the query touches sensitive fields like SSN or credit cards using exact word match."""
    q = query.lower()
    for word in SENSITIVE_KEYWORDS:
        if re.search(rf"\b{word}\b", q):
            return True
    if tables and "*" in q:
        for t in tables:
            if t in SENSITIVE_TABLES:
                return True
    return False


def check_authorization(user_role: str, action: str, tables: list) -> tuple:
    """Checks if the user's role is allowed to run this query."""
    role = user_role.lower()

    if role not in ROLE_PERMISSIONS:
        return False, f"Unknown role: {user_role}"

    if action.startswith("DDL") and role != "admin":
        return False, f"Role '{user_role}' is not allowed to run DDL commands"

    if action not in ROLE_PERMISSIONS[role]:
        return False, f"Role '{user_role}' is not allowed to perform {action}"

    for t in tables:
        if t in PROTECTED_TABLES and role != "admin":
            return False, f"Role '{user_role}' cannot access system table '{t}'"

    return True, None


# 3. Main VaultDB Client
class VaultClient:
    def __init__(self, host="127.0.0.1", port=5432, user="postgres", password="nimit8222", dbname="postgres"):
        self.dbname = dbname
        self.conn = psycopg.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            dbname=dbname,
            autocommit=True
        )

    def execute(self, query: str, params=None, app_user="anonymous", user_role="reader"):
        """Executes a query, checks permissions, and records the audit log."""
        action = extract_action(query)
        tables = extract_tables(query)
        target_str = ", ".join(tables) if tables else "unknown"
        is_sensitive = is_sensitive_query(query, tables)

        # 1. Check permissions
        allowed, reason = check_authorization(user_role, action, tables)
        if not allowed:
            self._log_audit(app_user, user_role, action, target_str, query, 0, is_sensitive, "DENIED", reason)
            raise PermissionError(f"Access Denied: {reason}")

        # 2. Run query in PostgreSQL
        rows_affected = 0
        status = "SUCCESS"
        error_msg = None
        results = []

        try:
            with self.conn.cursor() as cur:
                cur.execute(query, params)
                if cur.description is not None:
                    results = cur.fetchall()
                    rows_affected = len(results)
                else:
                    rows_affected = cur.rowcount if cur.rowcount != -1 else 0
            return results

        except Exception as e:
            status = "ERROR"
            error_msg = str(e)
            raise e

        finally:
            # 3. Always write the audit record
            self._log_audit(app_user, user_role, action, target_str, query, rows_affected, is_sensitive, status, error_msg)

    def _log_audit(self, user, role, action, target, query, rows, sensitive, status, error):
        sql = """
            INSERT INTO vault_audit.audit_logs 
            (app_user, user_role, action, target_table, database_name, query_text, rows_affected, is_sensitive, execution_status, error_message)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        try:
            with self.conn.cursor() as cur:
                cur.execute(sql, (user, role, action, target, self.dbname, query, rows, sensitive, status, error))
        except Exception as err:
            print("Audit write error:", err)

    def get_audit_logs(self, limit=10):
        """Fetches the latest audit logs from the database."""
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT log_id, logged_at, app_user, user_role, action, 
                       target_table, database_name, is_sensitive, execution_status, rows_affected 
                FROM vault_audit.audit_logs 
                ORDER BY log_id DESC 
                LIMIT %s
            """, (limit,))
            return cur.fetchall()

    def close(self):
        if self.conn and not self.conn.closed:
            self.conn.close()