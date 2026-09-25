import re
import psycopg

# 1. Simple Table Permissions
PERMISSIONS = {
    "customer": {
        "accounts": ["SELECT"],
        "transactions": ["SELECT"]
    },
    "employee": {
        "accounts": ["SELECT"],
        "transactions": ["SELECT", "UPDATE", "INSERT"]
    },
    "admin": {
        "users": ["SELECT", "INSERT", "UPDATE", "DELETE", "DDL"],
        "accounts": ["SELECT", "INSERT", "UPDATE", "DELETE", "DDL"],
        "transactions": ["SELECT", "INSERT", "UPDATE", "DELETE", "DDL"],
        "audit_logs": ["SELECT"]
    }
}

SQL_RESERVED = {"select", "from", "where", "join", "into", "table", "update", "set", "values", "delete"}


# 2. Query Helpers
def extract_action(query: str) -> str:
    q = query.strip().upper()
    for verb in ["DROP", "TRUNCATE", "ALTER", "CREATE", "DELETE", "UPDATE", "INSERT", "SELECT"]:
        if q.startswith(verb) or f" {verb} " in q:
            return f"DDL:{verb}" if verb in ["DROP", "TRUNCATE", "ALTER", "CREATE"] else verb
    return "UNKNOWN"


def extract_tables(query: str) -> list:
    tables = set()
    q = query.lower()
    matches = re.finditer(r'\b(from|into|update|table|join)\s+([a-zA-Z0-9_.]+)', q)
    for m in matches:
        t = m.group(2).split('.')[-1]
        if t not in SQL_RESERVED:
            tables.add(t)
    return sorted(list(tables))


def check_authorization(role: str, action: str, tables: list) -> tuple:
    role = role.lower()
    if role not in PERMISSIONS:
        return False, f"Unknown role: {role}"

    allowed_tables = PERMISSIONS[role]
    for t in tables:
        if t not in allowed_tables:
            return False, f"Role '{role}' cannot access table '{t}'"
        if action not in allowed_tables[t]:
            return False, f"Role '{role}' cannot perform {action} on '{t}'"

    return True, None


# 3. VaultDB Client
class VaultClient:
    def __init__(self, host="127.0.0.1", port=5432, user="vault_user", password="vault123", dbname="postgres"):
        self.dbname = dbname
        self.conn = psycopg.connect(
            host=host,
            port=port,
            user=user,
            password=password,
            dbname=dbname,
            autocommit=True
        )

    def get_role(self, email: str) -> str:
        """Looks up the user's role from app_data.users table."""
        try:
            with self.conn.cursor() as cur:
                cur.execute("SELECT role FROM app_data.users WHERE email = %s;", (email,))
                row = cur.fetchone()
                if row:
                    return row[0]
        except Exception:
            pass
        return "customer"

    def execute(self, query: str, params=None, app_user="alice@bank.com"):
        role = self.get_role(app_user)
        action = extract_action(query)
        tables = extract_tables(query)
        target_str = ", ".join(tables) if tables else "unknown"

        # Check permissions
        allowed, reason = check_authorization(role, action, tables)
        if not allowed:
            self._log_audit(app_user, role, action, target_str, query, "DENIED")
            raise PermissionError(f"Access Denied: {reason}")

        # Run query
        status = "SUCCESS"
        results = []
        self.last_rows_affected = 0
        self.last_columns = []
        try:
            with self.conn.cursor() as cur:
                cur.execute(query, params)
                if cur.description is not None:
                    results = cur.fetchall()
                    self.last_rows_affected = len(results)
                    self.last_columns = [desc[0] for desc in cur.description]
                else:
                    self.last_rows_affected = cur.rowcount if cur.rowcount != -1 else 0
                    self.last_columns = []
            return results
        except Exception as e:
            status = "ERROR"
            raise e
        finally:
            self._log_audit(app_user, role, action, target_str, query, status)

    def _log_audit(self, user, role, action, target, query, status):
        sql = """
            INSERT INTO vault_audit.audit_logs (app_user, user_role, action, target_table, query_text, execution_status)
            VALUES (%s, %s, %s, %s, %s, %s)
        """
        try:
            with self.conn.cursor() as cur:
                cur.execute(sql, (user, role, action, target, query, status))
        except Exception as err:
            print("Audit write error:", err)

    def get_audit_logs(self, limit=10):
        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT log_id, logged_at, app_user, user_role, action, target_table, execution_status, query_text
                FROM vault_audit.audit_logs 
                ORDER BY log_id DESC 
                LIMIT %s;
            """, (limit,))
            return cur.fetchall()

    def close(self):
        if self.conn and not self.conn.closed:
            self.conn.close()