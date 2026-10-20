"""
VaultDB Real-Time Alert & Slack Webhook Dispatcher
Dispatches formatted Slack/webhook alerts when genuine security anomalies are detected.
Persists alerts to disk (data/alerts.jsonl) and buffers recent events for the Security Center dashboard.
Prevents duplicate alerts for the same event.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import threading
import time
from typing import Any, Dict, List, Optional
import urllib.request

from config.settings import settings

logger = logging.getLogger(__name__)

ALERTS_LOG_PATH = Path("data/alerts.jsonl")


class AlertDispatcher:
    """Dispatches, buffers, and persists genuine real-time security alerts."""

    _recent_alerts: List[Dict[str, Any]] = []
    _lock = threading.Lock()
    # Cache of recent alert signatures for deduplication: {signature: timestamp}
    _dedup_cache: Dict[str, float] = {}
    DEDUP_WINDOW_SECONDS = 15.0

    @classmethod
    def dispatch_anomaly_alert(
        cls,
        app_user: str,
        user_role: str,
        anomalies: List[Any],
        query: str,
        rows_affected: int,
        execution_status: str = "SUCCESS",
        client_ip: str = "127.0.0.1",
        immudb_log_id: Optional[int] = None,
        target_table: Optional[str] = None,
        custom_summary: Optional[str] = None,
    ):
        """
        Dispatches, buffers, and persists genuine real-time security alerts.
        In-memory buffering and disk persistence happen synchronously to eliminate UI race conditions.
        External Slack notifications are dispatched asynchronously in background.
        """
        if not anomalies:
            return

        now_utc = datetime.now(timezone.utc)
        now_iso = now_utc.isoformat()

        for anom in anomalies:
            # Support both dict from AnomalyDetector.evaluate and raw strings
            if isinstance(anom, dict):
                name = anom.get("name", "Security Anomaly")
                explanation = anom.get("explanation", custom_summary or name)
                table = anom.get("table", target_table or "accounts")
                severity = anom.get("severity", "High")
                outcome = anom.get("outcome", "Blocked" if execution_status == "DENIED" else "Flagged")
            else:
                name = str(anom).replace("_", " ").title()
                explanation = custom_summary or f"Security anomaly detected for {app_user}"
                table = target_table or "accounts"
                severity = "High" if "DENIED" in execution_status or "UNAUTHORIZED" in str(anom) else "Medium"
                outcome = "Blocked" if execution_status == "DENIED" else "Flagged"

            alert_id = int(now_utc.timestamp() * 1000)

            # Slack Block Kit payload format
            slack_payload = {
                "text": f"VaultDB Alert: {name} by {app_user} ({outcome})",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"VaultDB Security Alert: {name}",
                            "emoji": True,
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*User:*\n`{app_user}` ({user_role})"},
                            {"type": "mrkdwn", "text": f"*Table:*\n`{table}`"},
                            {"type": "mrkdwn", "text": f"*Severity:*\n*{severity}*"},
                            {"type": "mrkdwn", "text": f"*Outcome:*\n*{outcome}*"},
                            {"type": "mrkdwn", "text": f"*Audit Log:*\n`#{immudb_log_id or '-'}`"},
                            {"type": "mrkdwn", "text": f"*Timestamp:*\n{now_iso}"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Explanation:*\n{explanation}\n\n*SQL Query:*\n```{query[:250]}```",
                        },
                    },
                ],
            }

            alert_record = {
                "id": alert_id,
                "timestamp": now_iso,
                "user": app_user,
                "role": user_role,
                "anomaly_name": name,
                "anomalies": [name],
                "explanation": explanation,
                "summary": explanation,
                "table": table,
                "severity": severity,
                "outcome": outcome,
                "query": query,
                "rows_affected": rows_affected,
                "status": execution_status,
                "immudb_log_id": immudb_log_id,
                "client_ip": client_ip,
                "slack_dispatched": False,
                "slack_payload": slack_payload,
            }

            # 1. Update in-memory buffer synchronously
            with cls._lock:
                if name == "Repeated Unauthorized Access":
                    # Remove older alert for this user so updated alert is placed at index 0 (top of table)
                    cls._recent_alerts = [
                        a for a in cls._recent_alerts
                        if not (a.get("user") == app_user and a.get("anomaly_name") == "Repeated Unauthorized Access")
                    ]
                else:
                    # Deduplicate: avoid duplicate alert for the exact same immudb log ID
                    if immudb_log_id and any(a.get("immudb_log_id") == immudb_log_id and a.get("anomaly_name") == name for a in cls._recent_alerts):
                        continue

                cls._recent_alerts.insert(0, alert_record)
                if len(cls._recent_alerts) > 50:
                    cls._recent_alerts = cls._recent_alerts[:50]

            # 2. Append to persistent log file synchronously
            try:
                ALERTS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
                with open(ALERTS_LOG_PATH, "a", encoding="utf-8") as f:
                    f.write(json.dumps(alert_record) + "\n")
            except Exception as e:
                logger.warning(f"Failed to persist alert record: {e}")

            # 3. Deliver Slack Webhook asynchronously in background thread
            webhook_url = getattr(settings, "SLACK_WEBHOOK_URL", "") or os.getenv("SLACK_WEBHOOK_URL", "")
            if webhook_url:
                threading.Thread(
                    target=cls._send_slack_webhook,
                    args=(webhook_url, slack_payload, alert_record),
                    daemon=True,
                ).start()

    @classmethod
    def _send_slack_webhook(cls, webhook_url: str, slack_payload: Dict[str, Any], alert_record: Dict[str, Any]):
        try:
            data_bytes = json.dumps(slack_payload).encode("utf-8")
            req = urllib.request.Request(
                webhook_url,
                data=data_bytes,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status == 200:
                    alert_record["slack_dispatched"] = True
                    logger.info(f"Dispatched Slack alert to {webhook_url[:30]}...")
        except Exception as e:
            logger.warning(f"Could not deliver real Slack webhook: {e}")

    @classmethod
    def _persist_recent_alerts_to_disk(cls):
        """Synchronizes in-memory recent alerts buffer to data/alerts.jsonl."""
        try:
            ALERTS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            records = list(reversed(cls._recent_alerts))
            with open(ALERTS_LOG_PATH, "w", encoding="utf-8") as f:
                for r in records:
                    f.write(json.dumps(r) + "\n")
        except Exception as e:
            logger.warning(f"Could not sync alerts to disk: {e}")

    @classmethod
    def get_recent_alerts(cls, limit: int = 20) -> List[Dict[str, Any]]:
        """Returns the most recent dispatched security alerts from memory or persistent disk."""
        with cls._lock:
            if cls._recent_alerts:
                return cls._recent_alerts[:limit]

        # Read from disk if in-memory buffer is empty
        if ALERTS_LOG_PATH.exists():
            records = []
            try:
                with open(ALERTS_LOG_PATH, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            data = json.loads(line)
                            # Exclude any legacy privilege events
                            name = data.get("anomaly_name") or (data.get("anomalies") and data.get("anomalies")[0]) or ""
                            if "PRIVILEGE_" not in name and "ELEVATION" not in name:
                                records.append(data)
                records.reverse()
                with cls._lock:
                    cls._recent_alerts = records[:50]
                return records[:limit]
            except Exception as e:
                logger.warning(f"Could not read alerts log: {e}")

        return []

    @classmethod
    def init_from_disk(cls):
        """Pre-populates the in-memory alerts buffer from disk at startup."""
        cls.get_recent_alerts(limit=50)


# Initialize in-memory alerts cache on module load
AlertDispatcher.init_from_disk()
