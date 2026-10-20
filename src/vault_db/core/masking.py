"""
VaultDB Dynamic Data Masking Module (V2 Scope)
Redacts sensitive PII attributes (SSN, payment card numbers, CVVs)
for unprivileged roles while preserving unmasked access for authorized admins/auditors.
"""

import re
from typing import Any, List, Set, Tuple


MASK_PATTERNS = {
    "ssn": re.compile(r"^\d{3}-\d{2}-\d{4}$"),
    "card": re.compile(r"^\d{4}-\d{4}-\d{4}-\d{4}$"),
}


from src.vault_db.core.crypto import decrypt_field


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
    Evaluates result columns and dynamically masks sensitive fields
    if user role is not 'admin' or 'auditor'.
    Also decrypts AES-256-GCM ciphertext columns stored at rest.
    Returns (masked_rows, was_masked, masked_column_names).
    """
    clean_role = user_role.lower()
    if clean_role in ("admin", "auditor"):
        # Privileged roles see decrypted business data
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
