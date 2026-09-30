"""
API Route Handlers for VaultDB Middleware
"""

from decimal import Decimal
from datetime import datetime, timezone
from typing import Any, List, Optional
from fastapi import APIRouter, HTTPException, Query, Request, Response

from src.vault_db.reports.pdf_generator import generate_audit_pdf_report
from src.vault_db.core.engine import VaultEngine
from src.vault_db.core.rbac import AccessDeniedError, QueryExecutionError
from src.vault_db.core.parser import SQLParser
from src.vault_db.api.models import (
    ExecuteQueryRequest,
    ExecuteQueryResponse,
    AuditLogEntry,
    VerifyLogResponse,
    LedgerStateResponse,
    SystemHealthResponse,
)

router = APIRouter(prefix="/api", tags=["VaultDB API"])

# Global engine instance attached during app startup
engine: VaultEngine = None


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
async def execute_query(req: ExecuteQueryRequest, request: Request):
    """
    Executes a SQL query under user identity context with RBAC and immudb audit trail.
    """
    eng = get_engine()
    client_ip = request.client.host if request.client else "127.0.0.1"

    try:
        res = eng.execute(
            query=req.query,
            params=tuple(req.params) if req.params else None,
            app_user=req.user,
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
    limit: int = Query(default=20, ge=1, le=100),
    source: str = Query(default="immudb", pattern="^(immudb|postgres)$")
):
    """
    Retrieves the latest audit logs from the immutable immudb ledger (or postgres fallback).
    """
    eng = get_engine()
    raw_logs = eng.get_audit_logs(limit=limit, source=source)
    return [AuditLogEntry(**entry) for entry in raw_logs]


@router.get("/verify/{log_id}", response_model=VerifyLogResponse)
async def verify_log(log_id: int):
    """
    Cryptographically verifies the authenticity and Merkle tree proof of an audit log in immudb.
    """
    eng = get_engine()
    result = eng.verify_audit_log(log_id)
    return VerifyLogResponse(**result)


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
    limit: int = Query(default=100, ge=1, le=500),
):
    """
    Exports a certified compliance PDF report from the immudb immutable audit trail.
    """
    eng = get_engine()
    raw_logs = eng.get_audit_logs(limit=limit, source="immudb")

    # Apply optional filters
    filtered_logs = raw_logs
    if user:
        filtered_logs = [l for l in filtered_logs if l.get("user") == user]
    if table:
        filtered_logs = [l for l in filtered_logs if l.get("table") and table in l.get("table")]
    if status:
        filtered_logs = [l for l in filtered_logs if l.get("status") == status]

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
    Returns metadata for all business tables in app_data schema.
    """
    eng = get_engine()
    tables_to_query = ["accounts", "transactions", "users", "compliance_policies"]
    results = []
    for t in tables_to_query:
        try:
            count_res, _, _ = eng.postgres.execute_query(f"SELECT COUNT(*) FROM app_data.{t};")
            row_count = count_res[0][0] if count_res else 0
        except Exception:
            row_count = 0
        results.append({
            "name": t,
            "schema": "app_data",
            "row_count": row_count,
        })
    return results


@router.get("/tables/{table_name}")
async def inspect_table_data(table_name: str, limit: int = 50, offset: int = 0):
    """
    Returns tabular data for exploring schema contents (accounts, transactions, users, compliance_policies).
    """
    allowed_tables = {"accounts", "transactions", "users", "compliance_policies"}
    clean_name = table_name.lower().strip()
    if clean_name not in allowed_tables:
        raise HTTPException(status_code=400, detail=f"Table '{table_name}' is not an accessible business table.")

    eng = get_engine()
    query = f"SELECT * FROM app_data.{clean_name} LIMIT {limit} OFFSET {offset};"
    rows, columns, _ = eng.postgres.execute_query(query)
    clean_rows = [
        [serialize_item(cell) for cell in row]
        for row in rows
    ]
    return {
        "table": clean_name,
        "columns": columns,
        "rows": clean_rows,
        "total_rows_returned": len(clean_rows),
    }


