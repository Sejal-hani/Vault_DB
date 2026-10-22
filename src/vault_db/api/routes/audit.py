"""
Audit, Verification, Ledger & Table Exploration Routes
Endpoints for audit log inspection, cryptographic Merkle tree verification,
tampering simulations, compliance PDF generation, and table schema browsing.
"""

import logging
import math
import psycopg
from datetime import datetime, timezone, timedelta
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, Response

from config.settings import settings
from src.vault_db.api.dependencies import get_engine, serialize_item
from src.vault_db.reports.pdf_generator import generate_audit_pdf_report
from src.vault_db.core.masking import mask_ssn
from src.vault_db.api.models import (
    AuditLogEntry,
    VerifyLogResponse,
    LedgerStateResponse,
    SystemHealthResponse,
    TamperPayload,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Audit & Compliance"])


@router.get("/logs", response_model=List[AuditLogEntry])
async def get_logs(
    limit: int = Query(default=100, ge=1, le=1000),
    source: str = Query(default="immudb", pattern="^(immudb|postgres)$"),
    user: Optional[str] = Query(default=None, description="Filter by user email"),
    table: Optional[str] = Query(default=None, description="Filter by table name"),
    status: Optional[str] = Query(default=None, description="Filter by status (SUCCESS, DENIED)"),
    time_range: Optional[str] = Query(default=None, description="Date filter (24h, 7d, 30d, all)"),
):
    """
    Retrieves the latest audit logs from the immutable immudb ledger (or postgres fallback).
    Supports filtering by user, table, status, and date range (last 24h, last 7 days, last 30 days).
    Supports retrieving up to 1,000 live audit records.
    """
    eng = get_engine()
    # Fetch an adequate window from immudb so that valid query records fill the requested limit
    fetch_limit = min(2000, max(500, limit * 2)) if (user or table or status or (time_range and time_range != "all")) else min(2000, max(200, limit + 50))
    if limit >= 1000:
        fetch_limit = 2000
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
        # Exclude login/authentication events, SQL execution error logs, and fictitious test tables
        if entry.get("action", "").startswith("AUTH:") or entry.get("status") == "ERROR" or entry.get("table") == "u":
            continue

        # Standardize enterprise banking personas
        if entry.get("role") in ("reader", "writer") or entry.get("user") in ("bob.reader@bank.com", "sarah.writer@bank.com"):
            entry["role"] = "employee"
            entry["user"] = "john@bank.com"

        # Evaluate genuine anomaly status (cross-referenced with immudb record and Security Alerts)
        is_anom = bool(entry.get("is_anomaly"))
        anom_flags = list(entry.get("anomalies") or [])

        if not is_anom:
            from src.vault_db.core.alerts import AlertDispatcher
            recent_alerts = AlertDispatcher.get_recent_alerts(limit=50)
            log_id = entry.get("id")
            for a in recent_alerts:
                if a.get("immudb_log_id") == log_id:
                    is_anom = True
                    anom_name = a.get("anomaly_name") or (a.get("anomalies") and a.get("anomalies")[0]) or "Security Anomaly"
                    if anom_name not in anom_flags:
                        anom_flags.append(anom_name)
                    break

        entry["is_anomaly"] = is_anom
        entry["anomalies"] = anom_flags

        if user and entry.get("user") != user:
            continue
        if table and (not entry.get("table") or table.lower() not in entry.get("table", "").lower()):
            continue
        if status == "SENSITIVE":
            if not entry.get("is_sensitive"):
                continue
        elif status and entry.get("status") != status:
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
async def simulate_tamper(payload: Optional[TamperPayload] = None, log_id: Optional[int] = Query(default=None)):
    """
    Simulates an attacker or rogue DBA tampering directly with PostgreSQL audit records.
    Uses admin connection to temporarily disable trigger and mutate a row in vault_audit.audit_logs.
    """
    eng = get_engine()
    target_id = payload.log_id if payload and payload.log_id is not None else log_id

    if not target_id:
        logs = eng.immudb.get_audit_logs(limit=1)
        if not logs:
            raise HTTPException(status_code=400, detail="No audit logs available in immudb to simulate tampering.")
        target_id = logs[0]["id"]

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
async def restore_tamper(payload: Optional[TamperPayload] = None, log_id: Optional[int] = Query(default=None)):
    """
    Restores a tampered PostgreSQL record back to its verified cryptographic immudb state.
    """
    target_id = payload.log_id if payload and payload.log_id is not None else log_id
    if not target_id:
        raise HTTPException(status_code=400, detail="Missing required 'log_id' parameter.")

    eng = get_engine()
    immu_res = eng.verify_audit_log(target_id)
    record = immu_res.get("record")
    if not record or not record.get("query_text"):
        raise HTTPException(status_code=400, detail=f"Cannot find authentic immudb record for log #{target_id}")

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
            """, (true_query, true_user, true_role, true_action, true_table, true_status, tx_id, target_id))
            cur.execute("ALTER TABLE vault_audit.audit_logs ENABLE TRIGGER trg_no_update_delete_audit;")

    return {
        "status": "RESTORED",
        "log_id": target_id,
        "restored_query": true_query,
        "message": f"Log #{target_id} has been restored to its authentic cryptographic immudb state."
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
    Queries the actual full totals across all historical audit records.
    """
    eng = get_engine()
    state = eng.get_ledger_state()

    total = 0
    success_count = 0
    denied_count = 0
    sensitive_count = 0

    try:
        res, _, _ = eng.postgres.execute_query("""
            SELECT 
                COUNT(*),
                COUNT(*) FILTER (WHERE execution_status = 'DENIED'),
                COUNT(*) FILTER (WHERE is_sensitive = TRUE),
                COUNT(*) FILTER (WHERE execution_status = 'SUCCESS')
            FROM vault_audit.audit_logs;
        """)
        if res and res[0]:
            total = int(res[0][0] or 0)
            denied_count = int(res[0][1] or 0)
            sensitive_count = int(res[0][2] or 0)
            success_count = int(res[0][3] or 0)

        # Synchronize with immudb primary ledger counter so total matches the latest immutable transactions
        try:
            counter_bytes = eng.immudb._client.get(eng.immudb.COUNTER_KEY).value
            immu_total = int(counter_bytes.decode("utf-8"))
            if immu_total > total:
                total = immu_total
                success_count = max(0, total - denied_count)
        except Exception:
            pass
    except Exception as e:
        logger.warning(f"Error querying Postgres for dashboard stats: {e}")
        logs = eng.get_audit_logs(limit=1000, source="immudb")
        total = len(logs)
        success_count = sum(1 for l in logs if l.get("status") == "SUCCESS")
        denied_count = sum(1 for l in logs if l.get("status") == "DENIED")
        sensitive_count = sum(1 for l in logs if l.get("is_sensitive", False))

    # Count active approved privilege grants
    active_grants_count = 0
    try:
        grants_res, _, _ = eng.postgres.execute_query("""
            SELECT COUNT(*) FROM app_data.access_requests 
            WHERE status = 'APPROVED' AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP);
        """)
        if grants_res and grants_res[0]:
            active_grants_count = int(grants_res[0][0] or 0)
    except Exception:
        pass

    # Count recent anomaly alerts
    anomaly_count = 0
    try:
        from src.vault_db.core.alerts import AlertDispatcher
        anomaly_count = len(AlertDispatcher.get_recent_alerts())
    except Exception:
        pass

    return {
        "total_audited": total,
        "success_count": success_count,
        "denied_count": denied_count,
        "sensitive_count": sensitive_count,
        "active_grants_count": active_grants_count,
        "anomaly_count": anomaly_count,
        "ledger_height": state.get("tx_id", 0),
        "root_hash": state.get("root_hash", ""),
        "database": state.get("database", "defaultdb"),
    }


@router.get("/reports/pdf")
async def export_pdf_report(
    user: Optional[str] = Query(default=None),
    role: Optional[str] = Query(default=None),
    table: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    customer: Optional[str] = Query(default=None, description="Scope report to access of customer personal records"),
    time_range: Optional[str] = Query(default=None, description="Date filter (24h, 7d, 30d, all)"),
    start_date: Optional[str] = Query(default=None),
    end_date: Optional[str] = Query(default=None),
    limit: int = Query(default=200, ge=1, le=1000),
):
    """
    Exports a certified compliance PDF report from the immudb immutable audit trail.
    Supports filtering by user, role, table, status, and date range.
    For customers, scopes the audit to all staff and systems that accessed their personal records.
    """
    eng = get_engine()
    raw_logs = eng.get_audit_logs(limit=limit, source="immudb")

    now = datetime.now(timezone.utc)
    cutoff_start = None
    cutoff_end = None

    if time_range == "24h":
        cutoff_start = now - timedelta(hours=24)
    elif time_range == "7d":
        cutoff_start = now - timedelta(days=7)
    elif time_range == "30d":
        cutoff_start = now - timedelta(days=30)

    if start_date:
        try:
            date_str = start_date + "T00:00:00" if len(start_date) == 10 else start_date
            s_dt = datetime.fromisoformat(date_str)
            if s_dt.tzinfo is None:
                s_dt = s_dt.replace(tzinfo=timezone.utc)
            cutoff_start = s_dt
        except Exception:
            pass

    if end_date:
        try:
            date_str = end_date + "T23:59:59" if len(end_date) == 10 else end_date
            e_dt = datetime.fromisoformat(date_str)
            if e_dt.tzinfo is None:
                e_dt = e_dt.replace(tzinfo=timezone.utc)
            cutoff_end = e_dt
        except Exception:
            pass

    # Apply optional filters
    filtered_logs = []
    for l in raw_logs:
        # Standardize enterprise personas
        if l.get("role") in ("reader", "writer") or l.get("user") in ("bob.reader@bank.com", "sarah.writer@bank.com"):
            l["role"] = "employee"
            l["user"] = "john@bank.com"

        if customer:
            # Customer audit: queries executed by customer OR queries accessing customer accounts/transactions data
            is_own_query = l.get("user") == customer
            touches_data = l.get("table") in ("accounts", "transactions")
            if not (is_own_query or touches_data):
                continue
        else:
            if user and l.get("user") != user:
                continue
            if role and l.get("role") and l.get("role").lower() != role.lower():
                continue
            if table and (not l.get("table") or table.lower() not in l.get("table", "").lower()):
                continue
            if status == "SENSITIVE":
                if not l.get("is_sensitive"):
                    continue
            elif status and l.get("status") != status:
                continue

        if l.get("time"):
            try:
                time_str = l["time"]
                if time_str.endswith("Z"):
                    time_str = time_str[:-1] + "+00:00"
                entry_dt = datetime.fromisoformat(time_str)
                if entry_dt.tzinfo is None:
                    entry_dt = entry_dt.replace(tzinfo=timezone.utc)
                if cutoff_start and entry_dt < cutoff_start:
                    continue
                if cutoff_end and entry_dt > cutoff_end:
                    continue
            except Exception:
                pass
        filtered_logs.append(l)

    ledger_state = eng.get_ledger_state()

    pdf_bytes = generate_audit_pdf_report(
        logs=filtered_logs,
        ledger_state=ledger_state,
        filter_user=customer if customer else user,
        filter_role=None if customer else role,
        filter_table=None if customer else table,
        filter_status=status,
        filter_time_range=time_range or (f"{start_date} to {end_date}" if start_date else None),
        approvals=None,
        anomalies=None,
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
        for t in ["accounts", "transactions", "users"]:
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

    # Determine deterministic ordering column (prefer 'id' if present, otherwise first column)
    col_check_sql = """
        SELECT column_name FROM information_schema.columns 
        WHERE table_schema = %s AND table_name = %s AND column_name = 'id';
    """
    col_check_res, _, _ = eng.postgres.execute_query(col_check_sql, (schema_name, clean_name))
    order_clause = "ORDER BY id ASC" if col_check_res else "ORDER BY 1 ASC"

    query = f'SELECT * FROM "{schema_name}"."{clean_name}" {order_clause} LIMIT {limit} OFFSET {calc_offset};'
    rows, columns, _ = eng.postgres.execute_query(query)

    ssn_indices = [i for i, col in enumerate(columns) if "ssn" in col.lower()]

    clean_rows = []
    for row in rows:
        row_list = [serialize_item(cell) for cell in row]
        for s_idx in ssn_indices:
            if s_idx < len(row_list) and row_list[s_idx] is not None:
                row_list[s_idx] = mask_ssn(row_list[s_idx])
        clean_rows.append(row_list)

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
