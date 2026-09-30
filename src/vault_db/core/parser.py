"""
SQL Query Parser and Inspector Module
Extracts verbs, affected target tables, and sensitive field accesses.
"""

import re
from dataclasses import dataclass, field
from typing import List, Set


SQL_RESERVED_KEYWORDS = {
    "select", "from", "where", "join", "into", "table", "update", "set",
    "values", "delete", "insert", "and", "or", "order", "by", "group", "having",
    "limit", "offset", "as", "on", "inner", "left", "right", "outer", "cross",
    "create", "drop", "alter", "truncate", "primary", "foreign", "key"
}

SENSITIVE_FIELD_NAMES = {
    "ssn", "password", "pwd", "secret", "credit_card", "card_number",
    "cvv", "pin", "salary", "token", "auth_token"
}


@dataclass
class QueryAnalysis:
    raw_query: str
    action: str
    tables: List[str] = field(default_factory=list)
    is_sensitive: bool = False
    sensitive_fields_found: List[str] = field(default_factory=list)
    is_ddl: bool = False


class SQLParser:
    """Parses and analyzes SQL statements for middleware policy checking and auditing."""

    @staticmethod
    def extract_action(query: str) -> str:
        q = query.strip()
        # Remove single-line comments
        q = re.sub(r'--.*$', '', q, flags=re.MULTILINE).strip().upper()

        ddl_verbs = ["DROP", "TRUNCATE", "ALTER", "CREATE"]
        for verb in ddl_verbs:
            if re.match(rf"^{verb}\b", q):
                return f"DDL:{verb}"

        dml_verbs = ["SELECT", "INSERT", "UPDATE", "DELETE"]
        for verb in dml_verbs:
            if re.match(rf"^{verb}\b", q):
                return verb

        # Fallback check inside query
        for verb in ddl_verbs:
            if f" {verb} " in q:
                return f"DDL:{verb}"
        for verb in dml_verbs:
            if f" {verb} " in q:
                return verb

        return "UNKNOWN"

    @staticmethod
    def extract_tables(query: str) -> List[str]:
        tables: Set[str] = set()
        q = query.lower()

        # Match table references after FROM, INTO, UPDATE, TABLE, JOIN
        matches = re.finditer(r'\b(from|into|update|table|join)\s+([a-zA-Z0-9_.]+)', q)
        for m in matches:
            token = m.group(2)
            # Remove schema if present (e.g. app_data.accounts -> accounts)
            clean_name = token.split('.')[-1].strip('`"\'[]')
            if clean_name and clean_name not in SQL_RESERVED_KEYWORDS:
                tables.add(clean_name)

        return sorted(list(tables))

    @staticmethod
    def detect_sensitive_fields(query: str) -> List[str]:
        q = query.lower()
        found = []
        for field_name in SENSITIVE_FIELD_NAMES:
            if re.search(rf'\b{field_name}\b', q):
                found.append(field_name)
        return sorted(found)

    @classmethod
    def analyze(cls, query: str) -> QueryAnalysis:
        action = cls.extract_action(query)
        tables = cls.extract_tables(query)
        sensitive = cls.detect_sensitive_fields(query)
        is_ddl = action.startswith("DDL")

        return QueryAnalysis(
            raw_query=query,
            action=action,
            tables=tables,
            is_sensitive=len(sensitive) > 0,
            sensitive_fields_found=sensitive,
            is_ddl=is_ddl
        )
