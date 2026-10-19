"""
VaultDB Anomaly Detection Engine (V2 Scope)
Detects suspicious enterprise access patterns: off-hours operations,
high-volume data exfiltration attempts, and rapid denial spikes.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class AnomalyDetector:
    """Evaluates query execution context for compliance and security anomalies."""

    VOLUME_THRESHOLD = 1000  # Queries returning > 1,000 rows flagged for review
    OFF_HOURS_START = 23    # 11:00 PM UTC
    OFF_HOURS_END = 5       # 05:00 AM UTC

    @classmethod
    def evaluate(
        cls,
        rows_affected: int,
        execution_status: str,
        user_role: str,
        is_sensitive: bool = False,
        timestamp: Optional[datetime] = None,
    ) -> List[str]:
        """
        Evaluates execution telemetry and returns active anomaly flags.
        """
        flags: List[str] = []
        now = timestamp or datetime.now(timezone.utc)
        hour = now.hour

        # 1. Off-Hours Access Detection
        if hour >= cls.OFF_HOURS_START or hour < cls.OFF_HOURS_END:
            flags.append("OFF_HOURS_ACTIVITY")

        # 2. High-Volume Bulk Data Exfiltration Alert
        if rows_affected >= cls.VOLUME_THRESHOLD:
            flags.append("BULK_DATA_ACCESS")

        # 3. Sensitive Data Access by Non-Admin
        if is_sensitive and user_role.lower() not in ("admin", "auditor"):
            flags.append("UNPRIVILEGED_PII_ACCESS")

        # 4. Security Violation Detected
        if execution_status == "DENIED":
            flags.append("POLICY_VIOLATION_BLOCKED")

        return flags
