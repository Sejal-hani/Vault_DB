import logging
import math
import psycopg
from decimal import Decimal
from datetime import datetime, timezone, timedelta
from typing import Any, List, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, HTTPException, Query, Request, Response, Depends, Header, Cookie

from config.settings import settings
from src.vault_db.reports.pdf_generator import generate_audit_pdf_report
from src.vault_db.core.engine import VaultEngine
from src.vault_db.core.rbac import AccessDeniedError, QueryExecutionError
from src.vault_db.core.parser import SQLParser
from src.vault_db.auth.security import verify_password
from src.vault_db.auth.jwt_handler import create_access_token
from src.vault_db.auth.dependencies import get_current_user, AuthenticatedUser
from src.vault_db.api.models import (
    ExecuteQueryRequest,
    ExecuteQueryResponse,
    AuditLogEntry,
    VerifyLogResponse,
    LedgerStateResponse,
    SystemHealthResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["VaultDB API"])

# Global engine instance attached during app startup
engine: VaultEngine = None


class LoginRequest(BaseModel):
    email: str
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    email: str
    role: str
    full_name: str
    api_key: Optional[str] = None
    department: str = "General"


@router.post("/auth/login", response_model=LoginResponse)
async def login(req: LoginRequest, response: Response, request: Request):
    """
    Authenticates email and password. Returns signed HS256 JWT and sets secure cookie.
    Logs authentication event into immudb.
    """
    eng = get_engine()
    user = eng.postgres.get_user_by_email(req.email)
    client_ip = request.client.host if request.client else "127.0.0.1"

    if not user or not verify_password(req.password, user.get("password_hash", "")):
        eng.immudb.append_audit_log(
            app_user=req.email,
            user_role="unknown",
            action="AUTH:LOGIN_FAILED",
            target_table="users",
            query_text=f"FAILED LOGIN ATTEMPT for {req.email}",
            execution_status="DENIED",
            client_ip=client_ip,
        )
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    token = create_access_token({
        "sub": user["email"],
        "role": user["role"],
        "name": user.get("full_name", user["email"]),
    })

    response.set_cookie(
        key="vault_session",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=3600,
    )

    eng.immudb.append_audit_log(
        app_user=user["email"],
        user_role=user["role"],
        action="AUTH:LOGIN_SUCCESS",
        target_table="users",
        query_text=f"USER AUTHENTICATED: {user['email']}",
        execution_status="SUCCESS",
        client_ip=client_ip,
    )

    return LoginResponse(
        access_token=token,
        email=user["email"],
        role=user["role"],
        full_name=user.get("full_name", user["email"]),
        api_key=user.get("api_key"),
        department=user.get("department", "General"),
    )


@router.post("/auth/demo-login/{persona}", response_model=LoginResponse)
async def demo_login(persona: str, response: Response, request: Request):
    """
    1-Click demo authentication for evaluation.
    Personas: admin, auditor, employee, customer.
    """
    credentials_map = {
        "admin": ("admin@bank.com", "AdminPass123!"),
        "auditor": ("compliance.lead@bank.com", "AuditorPass123!"),
        "employee": ("john@bank.com", "EmployeePass123!"),
        "customer": ("alice@bank.com", "CustomerPass123!"),
    }
    clean_p = persona.lower().strip()
    if clean_p not in credentials_map:
        raise HTTPException(status_code=400, detail=f"Unknown persona '{persona}'. Choose: admin, auditor, employee, customer.")

    email, password = credentials_map[clean_p]
    return await login(LoginRequest(email=email, password=password), response, request)


@router.post("/auth/logout")
async def logout(response: Response, request: Request):
    """Clears authentication session cookie."""
    response.delete_cookie(key="vault_session")
    return {"status": "LOGGED_OUT", "message": "Session invalidated."}


@router.get("/auth/me")
async def get_me(request: Request):
    """Returns currently authenticated user profile or unauthenticated status."""
    try:
        user = await get_current_user(request)
        return {
            "authenticated": True,
            "email": user.email,
            "role": user.role,
            "full_name": user.full_name,
            "api_key": user.api_key,
            "department": user.department,
        }
    except Exception:
        return {"authenticated": False}


def get_engine() -> VaultEngine:
    global engine
    if engine is None:
        engine = VaultEngine()
    return engine


def serialize_item(item: Any) -> Any:
    if isinstance(item, Decimal):
        return float(item)
    if isinstance(item, datetime):
        return item.isoformat()
    return item


@router.post("/execute", response_model=ExecuteQueryResponse)
async def execute_query(
    req: ExecuteQueryRequest,
    request: Request,
    authorization: Optional[str] = Header(None),
    x_api_key: Optional[str] = Header(None),
    vault_session: Optional[str] = Cookie(None),
):
    """
    Executes a SQL query under server-derived user identity context with RBAC, RLS, masking, and immudb audit trail.
    """
    eng = get_engine()
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Derive authenticated identity from Bearer token, Cookie, or X-API-Key
    authenticated_user = None
    try:
        authenticated_user = await get_current_user(request, authorization, x_api_key, vault_session)
    except Exception:
        pass

    # Use authenticated identity if present; otherwise fallback to request user or default
    resolved_user = authenticated_user.email if authenticated_user else (req.user or "alice@bank.com")

    try:
        res = eng.execute(
            query=req.query,
            params=tuple(req.params) if req.params else None,
            app_user=resolved_user,
            client_ip=client_ip,
        )

        clean_results = None
        if res.get("results"):
            clean_results = [
                [serialize_item(cell) for cell in row]
                for row in res["results"]
            ]

        return ExecuteQueryResponse(
            status="SUCCESS",
            results=clean_results,
            columns=res.get("columns", []),
            rows_affected=res.get("rows_affected", 0),
            execution_time_ms=res.get("execution_time_ms", 0.0),
            is_sensitive=res.get("is_sensitive", False),
            sensitive_fields=res.get("sensitive_fields", []),
            is_masked=res.get("is_masked", False),
            masked_fields=res.get("masked_fields", []),
            is_scoped=res.get("is_scoped", False),
            anomalies=res.get("anomalies", []),
            immudb_log_id=res.get("immudb_log_id"),
            immudb_tx_id=res.get("immudb_tx_id"),
            immudb_verified=res.get("immudb_verified"),
            immudb_tx_hash=res.get("immudb_tx_hash"),
        )
    except AccessDeniedError as pe:
        analysis = SQLParser.analyze(req.query)
        rec = getattr(pe, "immudb_record", {}) or {}
        return ExecuteQueryResponse(
            status="DENIED",
            error=str(pe),
            rows_affected=0,
            is_sensitive=analysis.is_sensitive,
            sensitive_fields=analysis.sensitive_fields_found,
            immudb_log_id=rec.get("id"),
            immudb_tx_id=rec.get("immudb_tx_id"),
            immudb_verified=rec.get("immudb_verified", True),
            immudb_tx_hash=rec.get("immudb_tx_hash"),
        )
    except QueryExecutionError as qe:
        analysis = SQLParser.analyze(req.query)
        rec = getattr(qe, "immudb_record", {}) or {}
        return ExecuteQueryResponse(
            status="ERROR",
            error=str(qe),
            rows_affected=0,
            is_sensitive=analysis.is_sensitive,
            sensitive_fields=analysis.sensitive_fields_found,
            immudb_log_id=rec.get("id"),
            immudb_tx_id=rec.get("immudb_tx_id"),
            immudb_verified=rec.get("immudb_verified", True),
            immudb_tx_hash=rec.get("immudb_tx_hash"),
        )
    except Exception as ex:
        analysis = SQLParser.analyze(req.query)
        return ExecuteQueryResponse(
            status="ERROR",
            error=str(ex),
            rows_affected=0,
            is_sensitive=analysis.is_sensitive,
            sensitive_fields=analysis.sensitive_fields_found,
        )


@router.get("/logs", response_model=List[AuditLogEntry])
async def get_logs(
    limit: int = Query(default=50, ge=1, le=1000),
    source: str = Query(default="immudb", pattern="^(immudb|postgres)$"),
    user: Optional[str] = Query(default=None, description="Filter by user email"),
    table: Optional[str] = Query(default=None, description="Filter by table name"),
    status: Optional[str] = Query(default=None, description="Filter by status (SUCCESS, DENIED, ERROR)"),
    time_range: Optional[str] = Query(default=None, description="Date filter (24h, 7d, 30d, all)"),
):
    """
    Retrieves the latest audit logs from the immutable immudb ledger (or postgres fallback).
    Supports filtering by user, table, status, and date range (last 24h, last 7 days, last 30 days).
    Supports watching up to 1,000 live audit records.
    """
    eng = get_engine()
    # If filters are requested, fetch a wider window to ensure filter coverage
    fetch_limit = max(1000, limit) if (user or table or status or (time_range and time_range != "all")) else limit
    raw_logs = eng.get_audit_logs(limit=fetch_limit, source=source)

    now = datetime.now(timezone.utc)
    cutoff = None
    if time_range == "24h":
        cutoff = now - timedelta(hours=24)
    elif time_range == "7d":
        cutoff = now - timedelta(days=7)
    elif time_range == "30d":
        cutoff = now - timedelta(days=30)

    filtered = []
    for entry in raw_logs:
        if user and entry.get("user") != user:
            continue
        if table and (not entry.get("table") or table.lower() not in entry.get("table", "").lower()):
            continue
        if status and entry.get("status") != status:
            continue
        if cutoff and entry.get("time"):
            try:
                time_str = entry["time"]
                if time_str.endswith("Z"):
                    time_str = time_str[:-1] + "+00:00"
                entry_dt = datetime.fromisoformat(time_str)
                if entry_dt.tzinfo is None:
                    entry_dt = entry_dt.replace(tzinfo=timezone.utc)
                if entry_dt < cutoff:
                    continue
            except Exception:
                pass

        filtered.append(entry)
        if len(filtered) >= limit:
            break

    return [AuditLogEntry(**entry) for entry in filtered]


@router.get("/verify/{log_id}", response_model=VerifyLogResponse)
async def verify_log(log_id: int):
    """
    Cryptographically verifies the authenticity and Merkle tree proof of an audit log in immudb.
    Also cross-verifies against the PostgreSQL relational mirror to detect any database tampering.
    """
    eng = get_engine()
    result = eng.verify_audit_log(log_id)

    # Cross-verify with PostgreSQL mirror record
    try:
        pg_res, _, _ = eng.postgres.execute_query(
            "SELECT query_text, execution_status, app_user FROM vault_audit.audit_logs WHERE log_id = %s;",
            (log_id,)
        )
        if pg_res:
            pg_query, pg_status, pg_user = pg_res[0]
            immudb_record = result.get("record", {}) or {}
            immu_query = immudb_record.get("query_text")
            immu_status = immudb_record.get("execution_status")
            immu_user = immudb_record.get("app_user")

            mismatches = []
            if immu_query and pg_query != immu_query:
                mismatches.append(f"SQL Statement Mismatch (PostgreSQL has: '{pg_query}' vs immudb sealed: '{immu_query}')")
            if immu_status and pg_status != immu_status:
                mismatches.append(f"Execution Status Mismatch (PostgreSQL: '{pg_status}' vs immudb: '{immu_status}')")
            if immu_user and pg_user != immu_user:
                mismatches.append(f"Identity Mismatch (PostgreSQL: '{pg_user}' vs immudb: '{immu_user}')")

            if mismatches:
                result["verified"] = False
                result["tamper_detected"] = True
                result["database_tampered"] = True
                result["mismatches"] = mismatches
                result["message"] = f"CRITICAL DATABASE TAMPERING DETECTED: PostgreSQL mirror does not match the immutable immudb Merkle root! {'; '.join(mismatches)}"
    except Exception as e:
        logger.warning(f"Could not cross-verify PostgreSQL mirror for log #{log_id}: {e}")

    return VerifyLogResponse(**result)


@router.post("/tamper-demo/simulate")
async def simulate_tamper(log_id: Optional[int] = None):
    """
    Simulates an attacker or rogue DBA tampering directly with PostgreSQL audit records.
    Uses admin connection to temporarily disable trigger and mutate a row in vault_audit.audit_logs.
    """
    eng = get_engine()

    if not log_id:
        logs = eng.immudb.get_audit_logs(limit=1)
        if not logs:
            raise HTTPException(status_code=400, detail="No audit logs available in immudb to simulate tampering.")
        target_id = logs[0]["id"]
    else:
        target_id = log_id

    immu_res = eng.verify_audit_log(target_id)
    orig_record = immu_res.get("record") or {}
    orig_q = orig_record.get("query_text", "SELECT * FROM app_data.accounts;")
    app_user = orig_record.get("app_user", "admin@bank.com")
    user_role = orig_record.get("user_role", "admin")
    action = orig_record.get("action", "SELECT")
    target_table = orig_record.get("target_table", "accounts")
    status = orig_record.get("execution_status", "SUCCESS")
    tx_id = immu_res.get("tx_id", 1)

    tampered_query = "SELECT balance FROM accounts; -- ALTERED BY ROGUE DBA DIRECTLY IN POSTGRES"

    admin_conninfo = settings.postgres_admin_conninfo
    with psycopg.connect(admin_conninfo, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("ALTER TABLE vault_audit.audit_logs DISABLE TRIGGER trg_no_update_delete_audit;")
            cur.execute("SELECT log_id FROM vault_audit.audit_logs WHERE log_id = %s;", (target_id,))
            exists = cur.fetchone()
            if not exists:
                cur.execute("""
                    INSERT INTO vault_audit.audit_logs 
                    (log_id, app_user, user_role, action, target_table, query_text, execution_status, immudb_tx_id)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                """, (target_id, app_user, user_role, action, target_table, tampered_query, status, tx_id))
            else:
                cur.execute("""
                    UPDATE vault_audit.audit_logs 
                    SET query_text = %s 
                    WHERE log_id = %s;
                """, (tampered_query, target_id))
            cur.execute("ALTER TABLE vault_audit.audit_logs ENABLE TRIGGER trg_no_update_delete_audit;")

    return {
        "status": "TAMPERED",
        "log_id": target_id,
        "original_query": orig_q,
        "tampered_query": tampered_query,
        "message": f"Log #{target_id} was altered in PostgreSQL. Click 'Verify Proof' to watch immudb detect the corruption!"
    }


@router.post("/tamper-demo/restore")
async def restore_tamper(log_id: int):
    """
    Restores a tampered PostgreSQL record back to its verified cryptographic immudb state.
    """
    eng = get_engine()
    immu_res = eng.verify_audit_log(log_id)
    record = immu_res.get("record")
    if not record or not record.get("query_text"):
        raise HTTPException(status_code=400, detail=f"Cannot find authentic immudb record for log #{log_id}")

    true_query = record["query_text"]
    true_user = record.get("app_user", "admin@bank.com")
    true_role = record.get("user_role", "admin")
    true_action = record.get("action", "SELECT")
    true_table = record.get("target_table", "accounts")
    true_status = record.get("execution_status", "SUCCESS")
    tx_id = immu_res.get("tx_id", 1)

    admin_conninfo = settings.postgres_admin_conninfo
    with psycopg.connect(admin_conninfo, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("ALTER TABLE vault_audit.audit_logs DISABLE TRIGGER trg_no_update_delete_audit;")
            cur.execute("""
                UPDATE vault_audit.audit_logs 
                SET query_text = %s,
                    app_user = %s,
                    user_role = %s,
                    action = %s,
                    target_table = %s,
                    execution_status = %s,
                    immudb_tx_id = %s
                WHERE log_id = %s;
            """, (true_query, true_user, true_role, true_action, true_table, true_status, tx_id, log_id))
            cur.execute("ALTER TABLE vault_audit.audit_logs ENABLE TRIGGER trg_no_update_delete_audit;")

    return {
        "status": "RESTORED",
        "log_id": log_id,
        "restored_query": true_query,
        "message": f"Log #{log_id} has been restored to its authentic cryptographic immudb state."
    }


@router.get("/ledger-state", response_model=LedgerStateResponse)
async def get_ledger_state():
    """
    Returns current immudb cryptographic root state (TxId and Merkle root hash).
    """
    eng = get_engine()
    state = eng.get_ledger_state()
    return LedgerStateResponse(**state)


@router.get("/health", response_model=SystemHealthResponse)
async def health_check():
    """
    Health check verifying connectivity to PostgreSQL and immudb.
    """
    eng = get_engine()
    pg_status = "healthy"
    immu_status = "healthy"

    try:
        eng.postgres.execute_query("SELECT 1;")
    except Exception as e:
        pg_status = f"unhealthy ({e})"

    try:
        eng.get_ledger_state()
    except Exception as e:
        immu_status = f"unhealthy ({e})"

    overall = "healthy" if pg_status == "healthy" and immu_status == "healthy" else "degraded"

    return SystemHealthResponse(
        status=overall,
        postgres=pg_status,
        immudb=immu_status,
        version="2.0.0",
    )


@router.get("/stats")
async def get_dashboard_stats():
    """
    Returns high-level compliance KPI metrics for the dashboard.
    """
    eng = get_engine()
    logs = eng.get_audit_logs(limit=100, source="immudb")
    state = eng.get_ledger_state()

    total = len(logs)
    success_count = sum(1 for l in logs if l.get("status") == "SUCCESS")
    denied_count = sum(1 for l in logs if l.get("status") == "DENIED")
    sensitive_count = sum(1 for l in logs if l.get("is_sensitive", False))

    return {
        "total_audited": total,
        "success_count": success_count,
        "denied_count": denied_count,
        "sensitive_count": sensitive_count,
        "ledger_height": state.get("tx_id", 0),
        "root_hash": state.get("root_hash", ""),
        "database": state.get("database", "defaultdb"),
    }


@router.get("/reports/pdf")
async def export_pdf_report(
    user: Optional[str] = Query(default=None),
    table: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    time_range: Optional[str] = Query(default=None, description="Date filter (24h, 7d, 30d, all)"),
    limit: int = Query(default=200, ge=1, le=1000),
):
    """
    Exports a certified compliance PDF report from the immudb immutable audit trail.
    Supports filtering by user, table, status, and date range.
    """
    eng = get_engine()
    raw_logs = eng.get_audit_logs(limit=limit, source="immudb")

    now = datetime.now(timezone.utc)
    cutoff = None
    if time_range == "24h":
        cutoff = now - timedelta(hours=24)
    elif time_range == "7d":
        cutoff = now - timedelta(days=7)
    elif time_range == "30d":
        cutoff = now - timedelta(days=30)

    # Apply optional filters
    filtered_logs = []
    for l in raw_logs:
        if user and l.get("user") != user:
            continue
        if table and (not l.get("table") or table.lower() not in l.get("table", "").lower()):
            continue
        if status and l.get("status") != status:
            continue
        if cutoff and l.get("time"):
            try:
                time_str = l["time"]
                if time_str.endswith("Z"):
                    time_str = time_str[:-1] + "+00:00"
                entry_dt = datetime.fromisoformat(time_str)
                if entry_dt.tzinfo is None:
                    entry_dt = entry_dt.replace(tzinfo=timezone.utc)
                if entry_dt < cutoff:
                    continue
            except Exception:
                pass
        filtered_logs.append(l)

    ledger_state = eng.get_ledger_state()

    pdf_bytes = generate_audit_pdf_report(
        logs=filtered_logs,
        ledger_state=ledger_state,
        filter_user=user,
        filter_table=table,
        filter_status=status,
    )

    filename = f"VaultDB_Audit_Report_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/tables")
async def list_schema_tables():
    """
    Returns metadata for all business tables dynamically discovered from PostgreSQL.
    Supports any custom schema and any external business tables.
    """
    eng = get_engine()
    results = []
    try:
        discovery_query = """
            SELECT table_schema, table_name 
            FROM information_schema.tables 
            WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
              AND table_type = 'BASE TABLE'
            ORDER BY 
                CASE WHEN table_schema = 'app_data' THEN 0 ELSE 1 END,
                table_name;
        """
        rows, _, _ = eng.postgres.execute_query(discovery_query)
        for r in rows:
            t_schema, t_name = r[0], r[1]
            try:
                count_res, _, _ = eng.postgres.execute_query(f'SELECT COUNT(*) FROM "{t_schema}"."{t_name}";')
                row_count = count_res[0][0] if count_res else 0
            except Exception:
                row_count = 0
            results.append({
                "name": t_name,
                "schema": t_schema,
                "row_count": row_count,
            })
    except Exception as e:
        logger.error(f"Error dynamically listing schema tables: {e}")
        for t in ["accounts", "transactions", "users", "compliance_policies"]:
            results.append({"name": t, "schema": "app_data", "row_count": 0})
    return results


@router.get("/tables/{table_name}")
async def inspect_table_data(
    table_name: str,
    limit: int = Query(default=50, ge=1, le=1000),
    page: Optional[int] = Query(default=None, ge=1),
    offset: Optional[int] = Query(default=None, ge=0),
):
    """
    Returns tabular data with pagination for exploring schema contents.
    Dynamically resolves table from any non-system PostgreSQL schema.
    Supports pagination parameters: limit, page, and offset.
    """
    clean_name = table_name.lower().strip()
    eng = get_engine()

    schema_query = """
        SELECT table_schema FROM information_schema.tables 
        WHERE LOWER(table_name) = %s 
          AND table_schema NOT IN ('pg_catalog', 'information_schema')
        ORDER BY CASE WHEN table_schema = 'app_data' THEN 0 ELSE 1 END
        LIMIT 1;
    """
    try:
        res, _, _ = eng.postgres.execute_query(schema_query, (clean_name,))
        if not res:
            raise HTTPException(status_code=400, detail=f"Table '{table_name}' is not an accessible business table.")
        schema_name = res[0][0]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database inspection error: {e}")

    # Determine pagination offset and current page
    if page is not None:
        calc_offset = (page - 1) * limit
        curr_page = page
    elif offset is not None:
        calc_offset = offset
        curr_page = (offset // limit) + 1
    else:
        calc_offset = 0
        curr_page = 1

    # Fetch total count
    try:
        count_res, _, _ = eng.postgres.execute_query(f'SELECT COUNT(*) FROM "{schema_name}"."{clean_name}";')
        total_count = count_res[0][0] if count_res else 0
    except Exception:
        total_count = 0

    total_pages = max(1, math.ceil(total_count / limit)) if total_count > 0 else 1

    query = f'SELECT * FROM "{schema_name}"."{clean_name}" LIMIT {limit} OFFSET {calc_offset};'
    rows, columns, _ = eng.postgres.execute_query(query)
    clean_rows = [
        [serialize_item(cell) for cell in row]
        for row in rows
    ]
    return {
        "table": clean_name,
        "schema": schema_name,
        "columns": columns,
        "rows": clean_rows,
        "total_count": total_count,
        "page": curr_page,
        "limit": limit,
        "offset": calc_offset,
        "total_pages": total_pages,
        "total_rows_returned": len(clean_rows),
    }


