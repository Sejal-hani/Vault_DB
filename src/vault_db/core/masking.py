"""
VaultDB Dynamic Data Masking Module (V2 Scope)
Redacts sensitive PII attributes (SSN, payment card numbers, CVVs)
for unprivileged roles and strips credential secrets (password_hash, api_key)
from all query results and schema explorations.
"""

import re
from typing import Any, List, Optional, Set, Tuple


HIDDEN_COLUMNS: Set[str] = {"password_hash", "api_key"}

MASK_PATTERNS = {
    "ssn": re.compile(r"^\d{3}-\d{2}-\d{4}$"),
    "card": re.compile(r"^\d{4}-\d{4}-\d{4}-\d{4}$"),
}


from src.vault_db.core.crypto import decrypt_field


def strip_hidden_columns(
    columns: List[str],
    rows: List[List[Any]],
    extra_hidden: Optional[Set[str]] = None,
) -> Tuple[List[str], List[List[Any]]]:
    """
    Strips security-sensitive credential columns (e.g. password_hash, api_key)
    and optional display-hidden columns (e.g. status) from both columns and rows.
    """
    deny_set = HIDDEN_COLUMNS | {s.lower() for s in (extra_hidden or set())}
    keep_indices = [i for i, col in enumerate(columns) if col.lower() not in deny_set]
    if len(keep_indices) == len(columns):
        return columns, rows

    new_columns = [columns[i] for i in keep_indices]
    new_rows = [[row[i] for i in keep_indices if i < len(row)] for row in rows]

    if isinstance(columns, list):
        columns[:] = new_columns

    return new_columns, new_rows


def mask_ssn(val: Any) -> str:
    """Decrypts if encrypted at rest, then masks SSN to '***-**-1234' format."""
    plain = decrypt_field(val)
    s = str(plain).strip()
    if len(s) >= 4:
        return f"***-**-{s[-4:]}"
    return "***-**-****"


def mask_card_number(val: Any) -> str:
    """Masks credit/debit card numbers to '****-****-****-1234' format."""
    s = str(val).strip()
    if len(s) >= 4:
        return f"****-****-****-{s[-4:]}"
    return "****-****-****-****"


def mask_cvv(val: Any) -> str:
    return "***"


def mask_query_text(query: str) -> str:
    """
    Sanitizes SQL query text by redacting embedded sensitive constants
    (SSNs, credit card numbers, CVVs, passwords) before writing to audit logs.
    Satisfies V2 Requirement: 'Mask in logs AND in results'.
    """
    if not query:
        return query
    q = query
    # Redact SSNs (e.g., 123-45-6789 -> ***-**-6789)
    q = re.sub(r'\b\d{3}-\d{2}-(\d{4})\b', r'***-**-\1', q)
    # Redact credit card numbers (e.g., 4111-2222-3333-4444 -> ****-****-****-4444)
    q = re.sub(r'\b(?:\d{4}[-\s]?){3}(\d{4})\b', r'****-****-****-\1', q)
    # Redact CVVs/PINs (e.g., cvv = '123' -> cvv = '***')
    q = re.sub(r'\b(cvv|pin)\s*=\s*[\'"]?\d{3,4}[\'"]?', r"\1='***'", q, flags=re.IGNORECASE)
    # Redact Passwords / Secrets
    q = re.sub(r'\b(password|pwd|secret)\s*=\s*[\'"][^\'"]+[\'"]', r"\1='[REDACTED]'", q, flags=re.IGNORECASE)
    return q


def mask_tabular_results(
    columns: List[str],
    rows: List[List[Any]],
    user_role: str,
) -> Tuple[List[List[Any]], bool, List[str]]:
    """
    Evaluates result columns, strips hidden credential columns (password_hash, api_key),
    and dynamically masks sensitive fields (SSN, card numbers, CVVs) for unprivileged roles.
    Only authorized 'admin' role receives decrypted business data.
    Returns (masked_rows, was_masked, masked_column_names).
    """
    # 1. Strip hidden credentials (password_hash, api_key) for ALL roles
    columns, rows = strip_hidden_columns(columns, rows)

    clean_role = user_role.lower()
    if clean_role == "admin":
        # Privileged admin role sees decrypted business data
        new_rows = []
        for row in rows:
            row_copy = list(row)
            for idx, col in enumerate(columns):
                if "ssn" in col.lower() and idx < len(row_copy):
                    row_copy[idx] = decrypt_field(row_copy[idx])
            new_rows.append(row_copy)
        return new_rows, False, []

    masked_cols = []
    mask_actions = {}

    for idx, col in enumerate(columns):
        col_lower = col.lower()
        if "ssn" in col_lower:
            mask_actions[idx] = mask_ssn
            masked_cols.append(col)
        elif "card" in col_lower or "credit" in col_lower or "pan" in col_lower:
            mask_actions[idx] = mask_card_number
            masked_cols.append(col)
        elif "cvv" in col_lower or "pin" in col_lower:
            mask_actions[idx] = mask_cvv
            masked_cols.append(col)

    if not mask_actions:
        return rows, False, []

    # Apply masking transformations
    new_rows = []
    for row in rows:
        row_copy = list(row)
        for col_idx, masker in mask_actions.items():
            if col_idx < len(row_copy) and row_copy[col_idx] is not None:
                row_copy[col_idx] = masker(row_copy[col_idx])
        new_rows.append(row_copy)

    return new_rows, True, masked_cols
