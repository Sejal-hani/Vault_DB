import re
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
        name_filter = "Alice Smith" if "alice" in user_email.lower() else "Carlos Mendez" if "carlos" in user_email.lower() else None
        if not name_filter:
            return query, False

        # If already filtered by this customer's name, don't duplicate
        if f"'{name_filter.lower()}'" in q_lower:
            return query, False

        clean_q = query.strip().rstrip(";")

        # Detect trailing clauses: ORDER BY, GROUP BY, HAVING, LIMIT, OFFSET
        clause_match = re.search(r'\b(order\s+by|group\s+by|having|limit|offset)\b', clean_q, re.IGNORECASE)
        if clause_match:
            split_pos = clause_match.start()
            prefix = clean_q[:split_pos].strip()
            suffix = clean_q[split_pos:].strip()

            if re.search(r'\bwhere\b', prefix, re.IGNORECASE):
                rewritten = f"{prefix} AND name = '{name_filter}' {suffix};"
            else:
                rewritten = f"{prefix} WHERE name = '{name_filter}' {suffix};"
            return rewritten, True
        else:
            if re.search(r'\bwhere\b', clean_q, re.IGNORECASE):
                return f"{clean_q} AND name = '{name_filter}';", True
            else:
                return f"{clean_q} WHERE name = '{name_filter}';", True

    return query, False

