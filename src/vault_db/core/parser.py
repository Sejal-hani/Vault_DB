"""
SQL Query Parser and Inspector Module
Extracts verbs, affected target tables, and sensitive field accesses.
Handles comments (single line, block comments, dollar quotes, strings), CTEs, and comma joins.
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
    "ssn", "password", "pwd", "secret", "api_key", "token", "auth_token"
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
        """
        Strips SQL comments while strictly preserving string literals,
        double-quoted identifiers, PostgreSQL dollar-quoted strings ($tag$...$tag$),
        and correctly stripping block comments (/* ... */) and line comments (--).
        """
        result = []
        i = 0
        n = len(sql)
        in_single = False
        in_double = False
        in_dollar = None

        while i < n:
            # Handle PostgreSQL dollar-quoted strings: $tag$...$tag$ or $$...$$
            if not in_single and not in_double and sql[i] == '$':
                if in_dollar is not None:
                    if sql.startswith(in_dollar, i):
                        result.append(in_dollar)
                        i += len(in_dollar)
                        in_dollar = None
                        continue
                else:
                    m = re.match(r'^\$[a-zA-Z0-9_]*\$', sql[i:])
                    if m:
                        tag = m.group(0)
                        in_dollar = tag
                        result.append(tag)
                        i += len(tag)
                        continue

            if in_dollar is not None:
                result.append(sql[i])
                i += 1
                continue

            # Handle single quotes
            if sql[i] == "'" and not in_double:
                if in_single:
                    if i + 1 < n and sql[i + 1] == "'":
                        result.append("''")
                        i += 2
                        continue
                    in_single = False
                else:
                    in_single = True
                result.append(sql[i])
                i += 1
                continue

            # Handle double quotes
            if sql[i] == '"' and not in_single:
                if in_double:
                    if i + 1 < n and sql[i + 1] == '"':
                        result.append('""')
                        i += 2
                        continue
                    in_double = False
                else:
                    in_double = True
                result.append(sql[i])
                i += 1
                continue

            # Handle comments outside of quotes
            if not in_single and not in_double:
                # Block comments /* ... */
                if sql[i:i + 2] == '/*':
                    end = sql.find('*/', i + 2)
                    if end != -1:
                        i = end + 2
                        result.append(' ')
                        continue
                    else:
                        break
                # Line comments -- ...
                if sql[i:i + 2] == '--':
                    end = sql.find('\n', i + 2)
                    if end != -1:
                        i = end + 1
                        result.append('\n')
                        continue
                    else:
                        break

            result.append(sql[i])
            i += 1

        return ''.join(result)

    @classmethod
    def split_statements(cls, sql: str) -> List[str]:
        """Splits SQL string into statements by semicolons outside of quotes and dollar-quotes."""
        statements = []
        current = []
        in_single = False
        in_double = False
        in_dollar = None
        i = 0
        n = len(sql)

        while i < n:
            char = sql[i]
            if not in_single and not in_double and char == '$':
                if in_dollar is not None:
                    if sql.startswith(in_dollar, i):
                        current.append(in_dollar)
                        i += len(in_dollar)
                        in_dollar = None
                        continue
                else:
                    m = re.match(r'^\$[a-zA-Z0-9_]*\$', sql[i:])
                    if m:
                        tag = m.group(0)
                        in_dollar = tag
                        current.append(tag)
                        i += len(tag)
                        continue

            if in_dollar is not None:
                current.append(char)
                i += 1
                continue

            if char == "'" and not in_double:
                in_single = not in_single
            elif char == '"' and not in_single:
                in_double = not in_double
            elif char == ';' and not in_single and not in_double:
                stmt = ''.join(current).strip()
                if stmt:
                    statements.append(stmt)
                current = []
                i += 1
                continue

            current.append(char)
            i += 1

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

        # Handle CTE (Common Table Expressions) WITH ...
        if q_upper.startswith("WITH"):
            q_lower = q.lower()
            if re.search(r'\b(delete\s+from|delete)\b', q_lower):
                return "DELETE"
            if re.search(r'\b(insert\s+into|insert)\b', q_lower):
                return "INSERT"
            if re.search(r'\b(update\s+[a-zA-Z0-9_.]+\s+set|update)\b', q_lower):
                return "UPDATE"
            return "SELECT"

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

    @staticmethod
    def extract_tables(query: str) -> List[str]:
        tables: Set[str] = set()
        q = query.lower()

        # Match table references after FROM, INTO, UPDATE, TABLE, JOIN, TRUNCATE
        matches = re.finditer(r'\b(from|into|update|table|join|truncate)\s+([a-zA-Z0-9_.]+)', q)
        for m in matches:
            token = m.group(2)
            # Remove schema if present (e.g. app_data.accounts -> accounts)
            clean_name = token.split('.')[-1].strip('`"\'[];')
            if clean_name and clean_name not in SQL_RESERVED_KEYWORDS:
                tables.add(clean_name)

        # Match comma-separated table joins in FROM clause (e.g. FROM accounts a, users u)
        from_matches = re.finditer(r'\bfrom\s+([^;]+?)(?:\bwhere\b|\bjoin\b|\bgroup\b|\border\b|\blimit\b|;|$)', q)
        for fm in from_matches:
            from_clause = fm.group(1)
            tokens = [t.strip() for t in from_clause.split(',')]
            for item in tokens:
                first_word = item.split()[0] if item else ''
                clean_name = first_word.split('.')[-1].strip('`"\'[];')
                if clean_name and clean_name not in SQL_RESERVED_KEYWORDS:
                    tables.add(clean_name)

        # Match table references after DROP TABLE, ALTER TABLE, DROP SCHEMA
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
