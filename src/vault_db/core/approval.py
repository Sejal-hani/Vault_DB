"""
VaultDB Access Request & Temporary Elevation Workflow (V2 Scope)
Implements: "Bob requests access for 24 hours, Manager approves, Auto-revokes after 24h, Logs the approval".
Enforces time-bounded privilege escalation with immutable audit trail.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from src.vault_db.storage.postgres import PostgresStorage
from src.vault_db.storage.immudb_vault import ImmudbVault
from src.vault_db.core.alerts import AlertDispatcher

logger = logging.getLogger(__name__)


class ApprovalManager:
    """Manages time-bounded privilege requests, manager approvals, and auto-revocation."""

    def __init__(self, postgres: Optional[PostgresStorage] = None, immudb: Optional[ImmudbVault] = None):
        self.postgres = postgres or PostgresStorage()
        self.immudb = immudb or ImmudbVault()

    def create_request(
        self,
        user_email: str,
        requested_role: str,
        requested_table: str = "*",
        duration_hours: int = 24,
        reason: str = "Required for maintenance and operations",
        client_ip: str = "127.0.0.1",
    ) -> Dict[str, Any]:
        """Submits a new access request and seals it in the immutable audit log."""
        clean_email = user_email.strip().lower()
        clean_role = requested_role.strip().lower()

        sql = """
            INSERT INTO app_data.access_requests 
            (user_email, requested_role, requested_table, duration_hours, reason, status)
            VALUES (%s, %s, %s, %s, %s, 'PENDING')
            RETURNING id, requested_at, status;
        """
        rows, cols, _ = self.postgres.execute_query(sql, (clean_email, clean_role, requested_table, duration_hours, reason))
        if not rows:
            raise RuntimeError("Could not insert access request into PostgreSQL.")

        req_id = rows[0][0]
        req_at = rows[0][1]

        # Log request creation in immudb audit trail
        try:
            self.immudb.append_audit_log(
                app_user=clean_email,
                user_role=clean_role,
                action="ACCESS_REQUEST:CREATED",
                target_table="access_requests",
                query_text=f"ACCESS REQUEST #{req_id}: {clean_email} requested role '{clean_role}' for {duration_hours}h (Reason: {reason})",
                execution_status="SUCCESS",
                client_ip=client_ip,
            )
        except Exception as e:
            logger.warning(f"Could not write request creation to immudb: {e}")

        return {
            "id": req_id,
            "user_email": clean_email,
            "requested_role": clean_role,
            "requested_table": requested_table,
            "duration_hours": duration_hours,
            "reason": reason,
            "status": "PENDING",
            "requested_at": str(req_at),
        }

    def list_requests(
        self,
        status: Optional[str] = None,
        user_email: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Lists access requests and automatically marks expired approvals."""
        self._check_and_expire_active_requests()

        where_clauses = []
        params = []
        if status:
            where_clauses.append("status = %s")
            params.append(status.upper())
        if user_email:
            where_clauses.append("user_email = %s")
            params.append(user_email.strip().lower())

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        sql = f"""
            SELECT id, user_email, requested_role, requested_table, duration_hours, reason,
                   status, requested_at, reviewed_by, reviewed_at, expires_at
            FROM app_data.access_requests
            {where_sql}
            ORDER BY id DESC;
        """
        rows, cols, _ = self.postgres.execute_query(sql, tuple(params) if params else None)
        results = []
        for r in rows:
            results.append({
                "id": r[0],
                "user_email": r[1],
                "requested_role": r[2],
                "requested_table": r[3],
                "duration_hours": r[4],
                "reason": r[5],
                "status": r[6],
                "requested_at": r[7].isoformat() if r[7] else None,
                "reviewed_by": r[8],
                "reviewed_at": r[9].isoformat() if r[9] else None,
                "expires_at": r[10].isoformat() if r[10] else None,
            })
        return results

    def approve_request(
        self,
        request_id: int,
        reviewer_email: str = "admin@bank.com",
        client_ip: str = "127.0.0.1",
    ) -> Dict[str, Any]:
        """Approves access request, sets expiration timestamp, and logs approval."""
        self.postgres.clear_role_cache()

        # Fetch request info
        sql_check = "SELECT id, user_email, requested_role, duration_hours, status FROM app_data.access_requests WHERE id = %s;"
        rows, _, _ = self.postgres.execute_query(sql_check, (request_id,))
        if not rows:
            raise ValueError(f"Access request #{request_id} does not exist.")

        req_id, user_email, role, hours, current_status = rows[0]
        if current_status != "PENDING":
            raise ValueError(f"Request #{request_id} cannot be approved because status is '{current_status}'.")

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=hours)

        sql_update = """
            UPDATE app_data.access_requests
            SET status = 'APPROVED',
                reviewed_by = %s,
                reviewed_at = %s,
                expires_at = %s
            WHERE id = %s
            RETURNING id, status, expires_at;
        """
        self.postgres.execute_query(sql_update, (reviewer_email, now, expires_at, request_id))

        # Sealed approval in immudb audit ledger
        try:
            self.immudb.append_audit_log(
                app_user=reviewer_email,
                user_role="admin",
                action="ACCESS_REQUEST:APPROVED",
                target_table="access_requests",
                query_text=f"ACCESS APPROVED: Request #{request_id} for {user_email} elevated to role '{role}' until {expires_at.isoformat()}",
                execution_status="SUCCESS",
                client_ip=client_ip,
            )
        except Exception as e:
            logger.warning(f"Could not record approval in immudb: {e}")

        return {
            "id": request_id,
            "status": "APPROVED",
            "user_email": user_email,
            "elevated_role": role,
            "approved_by": reviewer_email,
            "expires_at": expires_at.isoformat(),
            "message": f"Access granted. User '{user_email}' elevated to '{role}' for {hours} hours.",
        }

    def reject_request(
        self,
        request_id: int,
        reviewer_email: str = "admin@bank.com",
        reason: Optional[str] = None,
        client_ip: str = "127.0.0.1",
    ) -> Dict[str, Any]:
        """Rejects access request and logs rejection in audit trail."""
        sql_check = "SELECT id, user_email, requested_role, status FROM app_data.access_requests WHERE id = %s;"
        rows, _, _ = self.postgres.execute_query(sql_check, (request_id,))
        if not rows:
            raise ValueError(f"Access request #{request_id} does not exist.")

        req_id, user_email, role, current_status = rows[0]
        now = datetime.now(timezone.utc)

        sql_update = """
            UPDATE app_data.access_requests
            SET status = 'REJECTED',
                reviewed_by = %s,
                reviewed_at = %s
            WHERE id = %s;
        """
        self.postgres.execute_query(sql_update, (reviewer_email, now, request_id))

        try:
            self.immudb.append_audit_log(
                app_user=reviewer_email,
                user_role="admin",
                action="ACCESS_REQUEST:REJECTED",
                target_table="access_requests",
                query_text=f"ACCESS REJECTED: Request #{request_id} for {user_email} rejected by {reviewer_email}",
                execution_status="DENIED",
                client_ip=client_ip,
            )
        except Exception as e:
            logger.warning(f"Could not record rejection in immudb: {e}")

        return {
            "id": request_id,
            "status": "REJECTED",
            "user_email": user_email,
            "reviewed_by": reviewer_email,
            "message": f"Access request #{request_id} rejected.",
        }

    def revoke_request(
        self,
        request_id: int,
        reviewer_email: str = "admin@bank.com",
        client_ip: str = "127.0.0.1",
    ) -> Dict[str, Any]:
        """Manually revokes an active approved elevation ahead of schedule."""
        self.postgres.clear_role_cache()
        now = datetime.now(timezone.utc)
        sql = """
            UPDATE app_data.access_requests
            SET status = 'REVOKED',
                reviewed_by = %s,
                reviewed_at = %s
            WHERE id = %s
            RETURNING user_email, requested_role;
        """
        rows, _, _ = self.postgres.execute_query(sql, (reviewer_email, now, request_id))
        user_email = rows[0][0] if rows else "unknown"
        role = rows[0][1] if rows else "unknown"

        try:
            self.immudb.append_audit_log(
                app_user=reviewer_email,
                user_role="admin",
                action="ACCESS_REQUEST:REVOKED",
                target_table="access_requests",
                query_text=f"ACCESS REVOKED: Active elevation #{request_id} for {user_email} revoked by {reviewer_email}",
                execution_status="SUCCESS",
                client_ip=client_ip,
            )
        except Exception as e:
            logger.warning(f"Could not record revocation in immudb: {e}")

        return {
            "id": request_id,
            "status": "REVOKED",
            "user_email": user_email,
            "message": f"Access elevation for '{user_email}' has been revoked.",
        }

    def check_active_elevation(self, user_email: str) -> Optional[str]:
        """
        Returns active elevated role if the user has an unexpired approved request.
        Auto-revokes expired requests and records the expiration event.
        """
        clean_email = user_email.strip().lower()
        now = datetime.now(timezone.utc)

        sql = """
            SELECT id, requested_role, expires_at
            FROM app_data.access_requests
            WHERE user_email = %s AND status = 'APPROVED'
            ORDER BY expires_at DESC
            LIMIT 1;
        """
        rows, _, _ = self.postgres.execute_query(sql, (clean_email,))
        if not rows:
            return None

        req_id, role, expires_at = rows[0]
        if expires_at and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at and now >= expires_at:
            # Auto-revoke expired approval
            self.postgres.execute_query(
                "UPDATE app_data.access_requests SET status = 'EXPIRED' WHERE id = %s;",
                (req_id,)
            )
            try:
                self.immudb.append_audit_log(
                    app_user="system",
                    user_role="system",
                    action="ACCESS_REQUEST:EXPIRED",
                    target_table="access_requests",
                    query_text=f"ACCESS AUTO-REVOKED: Request #{req_id} for {clean_email} expired after designated duration.",
                    execution_status="SUCCESS",
                )
            except Exception:
                pass
            return None

        return role

    def _check_and_expire_active_requests(self):
        """Batch expires any active requests whose expires_at is past."""
        now = datetime.now(timezone.utc)
        sql_find = "SELECT id, user_email FROM app_data.access_requests WHERE status = 'APPROVED' AND expires_at <= %s;"
        rows, _, _ = self.postgres.execute_query(sql_find, (now,))
        for r in rows:
            req_id, email = r[0], r[1]
            self.postgres.execute_query(
                "UPDATE app_data.access_requests SET status = 'EXPIRED' WHERE id = %s;",
                (req_id,)
            )
            try:
                self.immudb.append_audit_log(
                    app_user="system",
                    user_role="system",
                    action="ACCESS_REQUEST:EXPIRED",
                    target_table="access_requests",
                    query_text=f"ACCESS AUTO-REVOKED: Request #{req_id} for {email} expired.",
                    execution_status="SUCCESS",
                )
            except Exception:
                pass
