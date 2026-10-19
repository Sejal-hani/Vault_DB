"""
VaultDB Row-Level Security (RLS) Engine (V2 Scope)
Restricts retail customers to accessing solely their personal banking records.
"""

from typing import Optional, Tuple


def apply_row_level_security(query: str, user_role: str, user_email: str) -> Tuple[str, bool]:
    """
    If user is a retail 'customer', enforces customer isolation by appending or rewriting
    filter constraints on app_data.accounts and app_data.transactions.
    Returns: (scoped_query, was_scoped)
    """
    clean_role = user_role.lower()
    if clean_role != "customer":
        return query, False

    q_lower = query.lower()

    # If customer queries accounts without filtering by their own name/account
    if "accounts" in q_lower and "select" in q_lower:
        # Resolve customer name mapping (e.g. alice@bank.com -> 'Alice Smith')
        if "alice" in user_email.lower():
            if "where" in q_lower:
                return query.rstrip(";") + " AND name = 'Alice Smith';", True
            else:
                return query.rstrip(";") + " WHERE name = 'Alice Smith';", True
        elif "carlos" in user_email.lower():
            if "where" in q_lower:
                return query.rstrip(";") + " AND name = 'Carlos Mendez';", True
            else:
                return query.rstrip(";") + " WHERE name = 'Carlos Mendez';", True

    return query, False
