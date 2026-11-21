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
    "ssn", "password", "pwd", "secret", "api_key", "token", "auth_token",
    "credit_card", "card_number", "card_no", "cvv", "pan"
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
    def strip_comments(sql: str) -> str:
        """Strips SQL comments (-- and /* */) without affecting strings inside quotes."""
        out = []
        i = 0
        n = len(sql)
        in_single = False
        in_double = False
        while i < n:
            c = sql[i]
            if c == "'" and not in_double:
                in_single = not in_single
                out.append(c)
                i += 1
                continue
            elif c == '"' and not in_single:
                in_double = not in_double
                out.append(c)
                i += 1
                continue
            if not in_single and not in_double:
                if c == '-' and i + 1 < n and sql[i + 1] == '-':
                    while i < n and sql[i] != '\n':
                        i += 1
                    continue
                if c == '/' and i + 1 < n and sql[i + 1] == '*':
                    i += 2
                    while i + 1 < n and not (sql[i] == '*' and i + 1 < n and sql[i + 1] == '/'):
                        i += 1
                    i += 2
                    continue
            out.append(c)
            i += 1
        return ''.join(out).strip()

    @classmethod
    def split_statements(cls, sql: str) -> List[str]:
        """Splits SQL string into statements by semicolons outside of quotes."""
        clean_sql = cls.strip_comments(sql)
        statements = []
        current = []
        in_single = False
        in_double = False
        for char in clean_sql:
            if char == "'" and not in_double:
                in_single = not in_single
            elif char == '"' and not in_single:
                in_double = not in_double
            elif char == ';' and not in_single and not in_double:
                stmt = ''.join(current).strip()
                if stmt:
                    statements.append(stmt)
                current = []
                continue
            current.append(char)
        last = ''.join(current).strip()
        if last:
            statements.append(last)
        return statements

    @classmethod
    def extract_action(cls, query: str) -> str:
        q = cls.strip_comments(query).strip()

        statements = cls.split_statements(q)
        if len(statements) > 1:
            return "MULTI_STATEMENT"

        q_upper = q.upper()

        # Handle Common Table Expressions (CTEs): check for data-modifying CTEs
        if re.search(r"^\s*WITH\b", q_upper):
            if re.search(r"\bDELETE\s+FROM\b", q_upper) or re.search(r"\bDELETE\b", q_upper):
                return "DELETE"
            if re.search(r"\bUPDATE\s+[A-Z0-9_.]+\s+SET\b", q_upper) or re.search(r"\bUPDATE\b", q_upper):
                return "UPDATE"
            if re.search(r"\bINSERT\s+INTO\b", q_upper) or re.search(r"\bINSERT\b", q_upper):
                return "INSERT"
            for verb in ["DROP", "TRUNCATE", "ALTER"]:
                if re.search(rf"\b{verb}\b", q_upper):
                    return f"DDL:{verb}"

        ddl_verbs = ["DROP", "TRUNCATE", "ALTER", "CREATE"]
        for verb in ddl_verbs:
            if re.match(rf"^{verb}\b", q_upper):
                return f"DDL:{verb}"

        dml_verbs = ["SELECT", "INSERT", "UPDATE", "DELETE"]
        for verb in dml_verbs:
            if re.match(rf"^{verb}\b", q_upper):
                return verb

        # Fallback check inside query
        for verb in ddl_verbs:
            if f" {verb} " in q_upper:
                return f"DDL:{verb}"
        for verb in dml_verbs:
            if f" {verb} " in q_upper:
                return verb

        return "UNKNOWN"

    @classmethod
    def extract_tables(cls, query: str) -> List[str]:
        tables: Set[str] = set()
        q = cls.strip_comments(query).lower()

        # 1. Comma-separated tables after FROM (e.g. FROM accounts a, users u)
        from_match = re.search(r'\bfrom\s+([^;\(\)]+?)(?:\bwhere\b|\bjoin\b|\bgroup\b|\border\b|\bhaving\b|\blimit\b|\bunion\b|;|$)', q)
        if from_match:
            table_clause = from_match.group(1)
            for part in table_clause.split(','):
                tokens = part.strip().split()
                if tokens:
                    raw_token = tokens[0]
                    clean_name = raw_token.split('.')[-1].strip('`"\'[];')
                    if clean_name and clean_name not in SQL_RESERVED_KEYWORDS and not clean_name.startswith('('):
                        tables.add(clean_name)

        # 2. Match table references after INTO, UPDATE, TABLE, JOIN, TRUNCATE
        matches = re.finditer(r'\b(into|update|table|join|truncate)\s+([a-zA-Z0-9_.]+)', q)
        for m in matches:
            token = m.group(2)
            clean_name = token.split('.')[-1].strip('`"\'[];')
            if clean_name and clean_name not in SQL_RESERVED_KEYWORDS:
                tables.add(clean_name)

        # 3. Match table references after DROP TABLE, ALTER TABLE, DROP SCHEMA
        drop_alter_matches = re.finditer(r'\b(?:drop|alter)\s+(?:table|schema)\s+([a-zA-Z0-9_.]+)', q)
        for m in drop_alter_matches:
            token = m.group(1)
            clean_name = token.split('.')[-1].strip('`"\'[];')
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
