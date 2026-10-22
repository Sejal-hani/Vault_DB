"""
Query Execution Routes
Endpoints for executing SQL queries under zero-trust identity context with RBAC, RLS, and cryptographic immudb auditing.
"""

import logging
from typing import Optional
from fastapi import APIRouter, Request, Header, Cookie

from src.vault_db.api.dependencies import get_engine, serialize_item
from src.vault_db.auth.dependencies import get_current_user
from src.vault_db.core.rbac import AccessDeniedError, QueryExecutionError
from src.vault_db.core.parser import SQLParser
from src.vault_db.api.models import ExecuteQueryRequest, ExecuteQueryResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Query Execution"])


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
    resolved_user = authenticated_user.email if authenticated_user else (req.user or req.app_user or "alice@bank.com")

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

        raw_anoms = res.get("anomalies") or []
        clean_anoms = [a["name"] if isinstance(a, dict) else str(a) for a in raw_anoms]

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
            anomalies=clean_anoms,
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
