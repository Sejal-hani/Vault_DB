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


def mask_ssn(val: Any) -> str:
    """Masks SSN to '***-**-1234' format."""
    s = str(val).strip()
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


def mask_tabular_results(
    columns: List[str],
    rows: List[List[Any]],
    user_role: str,
) -> Tuple[List[List[Any]], bool, List[str]]:
    """
    Evaluates result columns and dynamically masks sensitive fields
    if user role is not 'admin' or 'auditor'.
    Returns (masked_rows, was_masked, masked_column_names).
    """
    clean_role = user_role.lower()
    if clean_role in ("admin", "auditor"):
        # Privileged compliance roles see unmasked business data
        return rows, False, []

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
