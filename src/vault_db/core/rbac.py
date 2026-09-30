"""
Role-Based Access Control (RBAC) Module
Enforces table-level and action-level policies based on authenticated user roles.
"""

from typing import Dict, List, Set, Tuple, Optional


class AccessDeniedError(Exception):
    """Raised when an application user attempts an operation prohibited by RBAC policy."""
    pass


# Default role-to-table permissions
DEFAULT_ROLE_PERMISSIONS: Dict[str, Dict[str, Set[str]]] = {
    "customer": {
        "accounts": {"SELECT"},
        "transactions": {"SELECT"},
        "compliance_policies": {"SELECT"}
    },
    "employee": {
        "accounts": {"SELECT"},
        "transactions": {"SELECT", "UPDATE", "INSERT"},
        "compliance_policies": {"SELECT"}
    },
    "admin": {
        "users": {"SELECT", "INSERT", "UPDATE", "DELETE", "DDL"},
        "accounts": {"SELECT", "INSERT", "UPDATE", "DELETE", "DDL"},
        "transactions": {"SELECT", "INSERT", "UPDATE", "DELETE", "DDL"},
        "compliance_policies": {"SELECT", "INSERT", "UPDATE", "DELETE", "DDL"},
        "audit_logs": {"SELECT"}
    },
    "auditor": {
        "users": {"SELECT"},
        "accounts": {"SELECT"},
        "transactions": {"SELECT"},
        "compliance_policies": {"SELECT"},
        "audit_logs": {"SELECT"}
    }
}


class RBACManager:
    """Manages role-based authorization for database operations."""

    def __init__(self, permissions: Optional[Dict[str, Dict[str, Set[str]]]] = None):
        self.permissions = permissions or DEFAULT_ROLE_PERMISSIONS

    def check_authorization(self, role: str, action: str, tables: List[str]) -> Tuple[bool, Optional[str]]:
        """
        Validates if the specified role is permitted to perform 'action' on all specified 'tables'.
        Returns (is_allowed, denial_reason).
        """
        role = role.lower()
        if role not in self.permissions:
            return False, f"Unknown or unauthorized role: '{role}'"

        allowed_tables = self.permissions[role]

        # For queries that don't target a specific table (e.g. SELECT 1, SELECT CURRENT_TIMESTAMP)
        if not tables:
            return True, None

        for table in tables:
            clean_table = table.lower()
            if clean_table not in allowed_tables:
                return False, f"Role '{role}' is forbidden from accessing table '{clean_table}'"

            # Check action authorization
            allowed_actions = allowed_tables[clean_table]
            # Handle DDL actions (e.g. DDL:DROP)
            base_action = "DDL" if action.startswith("DDL") else action

            if base_action not in allowed_actions and action not in allowed_actions:
                return False, f"Role '{role}' is not permitted to perform {action} on table '{clean_table}'"

        return True, None
