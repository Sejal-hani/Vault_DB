"""
VaultDB Anomaly Detection Engine
Evaluates query execution context for genuine security anomalies:

1. Unusual Bulk Data Access: Queries retrieving unusually large customer records (> threshold).
2. Unusual After-Hours Access: Employees accessing sensitive customer data outside working hours (09:00 - 18:00 IST).
3. Repeated Unauthorized Access: Repeated policy violations (>= 3 denials in 5 minutes) by the same user.
4. Unusual Bulk Modification: Broad or high-impact UPDATE/DELETE statements (> threshold).
"""

from datetime import datetime, timezone, timedelta
import os
import re
import time
from typing import Any, Dict, List, Optional


class AnomalyDetector:
    """Evaluates query execution context for genuine compliance and security anomalies."""

    # Configurable thresholds
    BULK_ROW_THRESHOLD = int(os.getenv("BULK_ROW_THRESHOLD", "1000"))
    BULK_MODIFICATION_THRESHOLD = int(os.getenv("BULK_MODIFICATION_THRESHOLD", "10"))
    WORKING_HOURS_START_IST = int(os.getenv("WORKING_HOURS_START_IST", "9"))   # 09:00 IST
    WORKING_HOURS_END_IST = int(os.getenv("WORKING_HOURS_END_IST", "18"))     # 18:00 IST
    DENIAL_WINDOW_SECONDS = int(os.getenv("DENIAL_WINDOW_SECONDS", "300"))     # 5 minutes
    DENIAL_THRESHOLD = int(os.getenv("DENIAL_THRESHOLD", "2"))                 # >= 2 repeated denials (single denial not flagged)

    # Sliding window of denial timestamps per user: {user_email: [ts1, ts2, ...]}
    _denial_history: Dict[str, List[float]] = {}

    @classmethod
    def evaluate(
        cls,
        query: str = "",
        rows_affected: int = 0,
        execution_status: str = "SUCCESS",
        user_role: str = "",
        app_user: str = "",
        action: Optional[str] = None,
        target_table: Optional[str] = None,
        is_sensitive: bool = False,
        timestamp: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """
        Evaluates execution telemetry against the 4 defined anomaly rules.
        Returns a list of anomaly event objects with complete metadata.
        Ordinary single denials, standard queries, and privilege workflows are NEVER flagged.
        """
        anomalies: List[Dict[str, Any]] = []
        now_utc = timestamp or datetime.now(timezone.utc)
        clean_query = (query or "").strip()
        role_lower = (user_role or "").lower()
        effective_action = (action or "").upper()
        tbl_name = (target_table or "").lower()

        # -------------------------------------------------------------
        # Rule 1: Unusual Bulk Data Access
        # -------------------------------------------------------------
        # Flag non-admin queries attempting to retrieve large customer records (> threshold).
        # Administrators are fully authorized to inspect and export enterprise datasets.
        limit_match = re.search(r"\bLIMIT\s+(\d+)\b", clean_query, re.IGNORECASE) if clean_query else None
        requested_limit = int(limit_match.group(1)) if limit_match else None
        effective_count = max(rows_affected, requested_limit or 0)

        if role_lower != "admin" and (not effective_action or effective_action in ("SELECT", "BULK_DATA_ACCESS") or ("SELECT" in clean_query.upper() and effective_action != "MULTI_STATEMENT")):
            if effective_count >= cls.BULK_ROW_THRESHOLD:
                severity = "Critical" if effective_count >= 10000 else "Medium"
                outcome = "Blocked" if execution_status == "DENIED" else "Flagged"
                explanation = (
                    f"Retrieved {effective_count:,} records (configured threshold: {cls.BULK_ROW_THRESHOLD:,})"
                    if rows_affected > 0 else
                    f"Attempted bulk retrieval of {effective_count:,} records (configured threshold: {cls.BULK_ROW_THRESHOLD:,})"
                )
                anomalies.append({
                    "name": "Unusual Bulk Data Access",
                    "code": "BULK_DATA_ACCESS",
                    "BULK_DATA_ACCESS": True,
                    "explanation": explanation,
                    "table": tbl_name if tbl_name != "unknown" else "accounts",
                    "severity": severity,
                    "outcome": outcome,
                    "rows_affected": effective_count,
                })

        # -------------------------------------------------------------
        # Rule 2: Unusual After-Hours Access
        # -------------------------------------------------------------
        # Flag employees accessing sensitive customer data outside configured working hours (09:00 - 18:00 IST)
        # Retail customers legitimately access accounts 24/7; only internal employees are restricted to working hours.
        ist_offset = timezone(timedelta(hours=5, minutes=30))
        now_ist = now_utc.astimezone(ist_offset)
        ist_hour = now_ist.hour
        is_outside_working_hours = (ist_hour < cls.WORKING_HOURS_START_IST or ist_hour >= cls.WORKING_HOURS_END_IST)

        if is_outside_working_hours and role_lower in ("employee", "staff"):
            # Check if accessing sensitive customer tables or sensitive PII
            targets_customer_data = any(t in tbl_name for t in ("account", "transaction", "user", "customer")) or is_sensitive
            if targets_customer_data:
                outcome = "Blocked" if execution_status == "DENIED" else "Flagged"
                anomalies.append({
                    "name": "Unusual After-Hours Access",
                    "explanation": f"Employee accessed sensitive customer data outside working hours ({now_ist.strftime('%H:%M')} IST; business hours: 09:00 - 18:00 IST)",
                    "table": tbl_name if tbl_name != "unknown" else "accounts",
                    "severity": "High",
                    "outcome": outcome,
                    "rows_affected": rows_affected,
                })

        # -------------------------------------------------------------
        # Rule 3: Repeated Unauthorized Access
        # -------------------------------------------------------------
        # Flag repeated denied access attempts by the same user within a configurable window (>= 3 denials in 5 min)
        # Single individual denials are intentionally NOT flagged.
        if execution_status == "DENIED" and app_user:
            now_ts = time.time()
            user_denials = cls._denial_history.setdefault(app_user, [])
            user_denials.append(now_ts)
            # Prune denials older than configured window
            cls._denial_history[app_user] = [t for t in user_denials if now_ts - t <= cls.DENIAL_WINDOW_SECONDS]
            denial_count = len(cls._denial_history[app_user])

            if denial_count >= cls.DENIAL_THRESHOLD:
                anomalies.append({
                    "name": "Repeated Unauthorized Access",
                    "explanation": f"User triggered {denial_count} unauthorized access denials within 5 minutes (configured threshold: {cls.DENIAL_THRESHOLD})",
                    "table": tbl_name if tbl_name != "unknown" else "security_policy",
                    "severity": "High",
                    "outcome": "Blocked",
                    "rows_affected": 0,
                })

        # -------------------------------------------------------------
        # Rule 4: Unusual Bulk Modification
        # -------------------------------------------------------------
        # Flag unusually large UPDATE or DELETE operations (> threshold rows or broad condition)
        is_modification = effective_action in ("UPDATE", "DELETE") or re.search(r"\b(UPDATE|DELETE\s+FROM)\b", clean_query, re.IGNORECASE)
        if is_modification:
            # Check if affecting >= threshold rows or broad query without specific id filter
            has_narrow_pk = bool(re.search(r"\bWHERE\s+[a-zA-Z0-9_\.]*id\s*=\s*\d+\b", clean_query, re.IGNORECASE))
            is_broad_modification = (rows_affected >= cls.BULK_MODIFICATION_THRESHOLD) or (not has_narrow_pk and re.search(r"\b(WHERE\s+1\s*=\s*1|WHERE\s+true|\bWHERE\s+[a-zA-Z0-9_]+\s*>\s*0)\b", clean_query, re.IGNORECASE))

            if is_broad_modification or rows_affected >= cls.BULK_MODIFICATION_THRESHOLD:
                outcome = "Blocked" if execution_status == "DENIED" else "Flagged"
                count_info = f"{rows_affected:,} records" if rows_affected > 0 else "unrestricted rows"
                anomalies.append({
                    "name": "Unusual Bulk Modification",
                    "explanation": f"Bulk {effective_action or 'modification'} attempted on {count_info} (configured threshold: {cls.BULK_MODIFICATION_THRESHOLD})",
                    "table": tbl_name if tbl_name != "unknown" else "accounts",
                    "severity": "Critical",
                    "outcome": outcome,
                    "rows_affected": rows_affected,
                })

        return anomalies
