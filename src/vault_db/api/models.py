"""
Pydantic Schemas for API Requests and Responses
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------
# Authentication Models
# ---------------------------------------------------------

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


# ---------------------------------------------------------
# Query Execution Models
# ---------------------------------------------------------

class ExecuteQueryRequest(BaseModel):
    query: str = Field(..., description="SQL statement to execute")
    user: Optional[str] = Field(default=None, description="Optional legacy fallback identity")
    app_user: Optional[str] = Field(default=None, description="Optional application user identity")
    params: Optional[List[Any]] = Field(default=None, description="Optional parameterized arguments")


class ExecuteQueryResponse(BaseModel):
    status: str
    results: Optional[List[List[Any]]] = None
    columns: Optional[List[str]] = None
    rows_affected: int = 0
    execution_time_ms: float = 0.0
    is_sensitive: bool = False
    sensitive_fields: Optional[List[str]] = None
    is_masked: bool = False
    masked_fields: Optional[List[str]] = None
    is_scoped: bool = False
    anomalies: Optional[List[str]] = None
    immudb_log_id: Optional[int] = None
    immudb_tx_id: Optional[int] = None
    immudb_verified: Optional[bool] = None
    immudb_tx_hash: Optional[str] = None
    error: Optional[str] = None


# ---------------------------------------------------------
# Audit, Ledger & Tamper Simulation Models
# ---------------------------------------------------------

class AuditLogEntry(BaseModel):
    id: int
    time: Optional[str] = None
    user: Optional[str] = None
    role: Optional[str] = None
    action: Optional[str] = None
    table: Optional[str] = None
    status: Optional[str] = None
    query: Optional[str] = None
    is_sensitive: bool = False
    immudb_tx_id: Optional[int] = None
    is_anomaly: bool = False
    anomalies: Optional[List[str]] = None


class FieldDiff(BaseModel):
    field: str
    sealed: Optional[str] = None
    current: Optional[str] = None


class VerifyLogResponse(BaseModel):
    log_id: int
    immudb_key: Optional[str] = None
    tx_id: Optional[int] = None
    verified: bool
    tamper_detected: bool
    database_tampered: bool = False
    ledger_integrity: bool = True
    mirror_match: bool = True
    diffs: Optional[List[FieldDiff]] = None
    mismatches: Optional[List[str]] = None
    current_root_hash: Optional[str] = None
    record: Optional[Dict[str, Any]] = None
    message: str
    error: Optional[str] = None


class LedgerStateResponse(BaseModel):
    database: str
    tx_id: int
    root_hash: str
    verified: bool


class SystemHealthResponse(BaseModel):
    status: str
    postgres: str
    immudb: str
    version: str


class TamperPayload(BaseModel):
    log_id: Optional[int] = None


# ---------------------------------------------------------
# Access Request & Approval Models
# ---------------------------------------------------------

class CreateAccessRequest(BaseModel):
    user_email: str
    requested_role: str = "writer"
    requested_table: str = "*"
    duration_hours: int = 24
    reason: str = "Need write access to update customer and transaction records for maintenance."
