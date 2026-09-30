"""
Pydantic Schemas for API Requests and Responses
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ExecuteQueryRequest(BaseModel):
    user: str = Field(default="alice@bank.com", description="Application user email/identity")
    query: str = Field(..., description="SQL statement to execute")
    params: Optional[List[Any]] = Field(default=None, description="Optional parameterized arguments")


class ExecuteQueryResponse(BaseModel):
    status: str
    results: Optional[List[List[Any]]] = None
    columns: Optional[List[str]] = None
    rows_affected: int = 0
    execution_time_ms: float = 0.0
    is_sensitive: bool = False
    sensitive_fields: Optional[List[str]] = None
    immudb_log_id: Optional[int] = None
    immudb_tx_id: Optional[int] = None
    immudb_verified: Optional[bool] = None
    immudb_tx_hash: Optional[str] = None
    error: Optional[str] = None


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


class VerifyLogResponse(BaseModel):
    log_id: int
    immudb_key: Optional[str] = None
    tx_id: Optional[int] = None
    verified: bool
    tamper_detected: bool
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
