import re
from typing import Optional, Tuple


def _inject_where_clause(query: str, scope_clause: str) -> str:
    clean_q = query.strip().rstrip(";")
    clause_match = re.search(r'\b(order\s+by|group\s+by|having|limit|offset)\b', clean_q, re.IGNORECASE)
    if clause_match:
        split_pos = clause_match.start()
        prefix = clean_q[:split_pos].strip()
        suffix = clean_q[split_pos:].strip()
        where_match = re.search(r'\bwhere\b', prefix, re.IGNORECASE)
        if where_match:
            where_pos = where_match.end()
            before_where = prefix[:where_match.start()].strip()
            existing_cond = prefix[where_pos:].strip()
            return f"{before_where} WHERE ({existing_cond}) AND ({scope_clause}) {suffix};"
        else:
            return f"{prefix} WHERE ({scope_clause}) {suffix};"
    else:
        where_match = re.search(r'\bwhere\b', clean_q, re.IGNORECASE)
        if where_match:
            where_pos = where_match.end()
            before_where = clean_q[:where_match.start()].strip()
            existing_cond = clean_q[where_pos:].strip()
            return f"{before_where} WHERE ({existing_cond}) AND ({scope_clause});"
        else:
            return f"{clean_q} WHERE ({scope_clause});"


def apply_row_level_security(query: str, user_role: str, user_email: str) -> Tuple[str, bool]:
    """
    If user is a retail 'customer', enforces customer isolation by appending or rewriting
    filter constraints on app_data.accounts and app_data.transactions.
    Returns: (scoped_query, was_scoped)
    """
    clean_role = user_role.lower()
    if clean_role != "customer":
        return query, False

    clean_email = user_email.strip().lower()
    if not clean_email:
        return query, False

    q_lower = query.lower()

    # 1. Accounts table scoping
    if "accounts" in q_lower and "select" in q_lower:
        if f"email = '{clean_email}'" in q_lower:
            return query, False
        scope_clause = f"user_id = (SELECT id FROM app_data.users WHERE email = '{clean_email}')"
        return _inject_where_clause(query, scope_clause), True

    # 2. Transactions table scoping
    if "transactions" in q_lower and "select" in q_lower:
        if f"email = '{clean_email}'" in q_lower:
            return query, False
        scope_clause = f"account_id IN (SELECT id FROM app_data.accounts WHERE user_id = (SELECT id FROM app_data.users WHERE email = '{clean_email}'))"
        return _inject_where_clause(query, scope_clause), True

    return query, False


