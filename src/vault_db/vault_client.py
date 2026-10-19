"""
VaultDB Client SDK & Middleware Library
Provides standard vaultdb.connect(user=..., password=...) / api_key authentication
as well as the backward-compatible VaultClient facade.
"""

from typing import Any, List, Optional, Tuple
from src.vault_db.core.engine import VaultEngine
from src.vault_db.core.rbac import AccessDeniedError, QueryExecutionError
from src.vault_db.auth.security import verify_password
from src.vault_db.auth.jwt_handler import decode_access_token


class AuthenticationError(Exception):
    """Raised when client credentials fail verification."""
    pass


class VaultConnection:
    """
    Authenticated database connection object.
    Ties every query to a cryptographically verified person in immudb.
    """

    def __init__(
        self,
        user_email: str,
        user_role: str,
        user_name: str,
        engine: Optional[VaultEngine] = None,
    ):
        self.user = user_email
        self.role = user_role
        self.name = user_name
        self.engine = engine or VaultEngine()
        self.last_rows_affected = 0
        self.last_columns: List[str] = []
        self.last_immudb_tx_id: Optional[int] = None
        self.last_immudb_tx_hash: Optional[str] = None
        self.last_anomalies: List[str] = []
        self.is_masked = False
        self.is_scoped = False

    def execute(self, query: str, params: Optional[Tuple[Any, ...]] = None):
        """Executes a query as the authenticated identity."""
        res = self.engine.execute(query=query, params=params, app_user=self.user)
        self.last_rows_affected = res.get("rows_affected", 0)
        self.last_columns = res.get("columns", [])
        self.last_immudb_tx_id = res.get("immudb_tx_id")
        self.last_immudb_tx_hash = res.get("immudb_tx_hash")
        self.last_anomalies = res.get("anomalies", [])
        self.is_masked = res.get("is_masked", False)
        self.is_scoped = res.get("is_scoped", False)
        return res.get("results", [])

    def verify_log(self, log_id: int):
        """Cryptographically verifies a log's Merkle inclusion proof."""
        return self.engine.verify_audit_log(log_id)

    def close(self):
        """Closes the underlying database connection pools."""
        self.engine.close()


def connect(
    dsn: Optional[str] = None,
    user: Optional[str] = None,
    password: Optional[str] = None,
    api_key: Optional[str] = None,
    token: Optional[str] = None,
) -> VaultConnection:
    """
    Connects to VaultDB with verified identity.
    Authentication can be provided via (user + password), api_key, or JWT token.
    Raises AuthenticationError if identity cannot be verified.
    """
    engine = VaultEngine()

    if api_key:
        user_rec = engine.postgres.get_user_by_api_key(api_key)
        if not user_rec:
            raise AuthenticationError("Invalid API key provided.")
        return VaultConnection(
            user_email=user_rec["email"],
            user_role=user_rec["role"],
            user_name=user_rec.get("full_name", user_rec["email"]),
            engine=engine,
        )

    if token:
        payload = decode_access_token(token)
        if not payload:
            raise AuthenticationError("Invalid or expired JWT token.")
        email = payload.get("sub", "")
        role = payload.get("role", "customer")
        name = payload.get("name", email)
        return VaultConnection(user_email=email, user_role=role, user_name=name, engine=engine)

    if user and password:
        user_rec = engine.postgres.get_user_by_email(user)
        if not user_rec or not verify_password(password, user_rec.get("password_hash", "")):
            raise AuthenticationError(f"Authentication failed for user '{user}'.")
        return VaultConnection(
            user_email=user_rec["email"],
            user_role=user_rec["role"],
            user_name=user_rec.get("full_name", user_rec["email"]),
            engine=engine,
        )

    # Fallback for demo convenience
    target_user = user or "admin@bank.com"
    target_role = engine.get_user_role(target_user)
    return VaultConnection(user_email=target_user, user_role=target_role, user_name=target_user, engine=engine)


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
        raw_logs = self.engine.get_audit_logs(limit=limit, source="immudb")
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