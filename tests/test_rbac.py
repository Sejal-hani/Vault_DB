"""
Unit Tests for RBAC Engine
"""

import pytest
from src.vault_db.core.rbac import RBACManager, DEFAULT_ROLE_PERMISSIONS


def test_customer_permissions():
    rbac = RBACManager()
    
    # Allowed
    allowed, _ = rbac.check_authorization("customer", "SELECT", ["accounts"])
    assert allowed is True
    
    allowed, _ = rbac.check_authorization("customer", "SELECT", ["transactions"])
    assert allowed is True

    # Denied
    allowed, reason = rbac.check_authorization("customer", "INSERT", ["transactions"])
    assert allowed is False
    assert "not permitted" in reason

    allowed, reason = rbac.check_authorization("customer", "SELECT", ["users"])
    assert allowed is False
    assert "forbidden" in reason


def test_employee_permissions():
    rbac = RBACManager()

    # Allowed
    allowed, _ = rbac.check_authorization("employee", "SELECT", ["accounts"])
    assert allowed is True

    allowed, _ = rbac.check_authorization("employee", "UPDATE", ["transactions"])
    assert allowed is True

    # Denied: Modifying balance
    allowed, reason = rbac.check_authorization("employee", "UPDATE", ["accounts"])
    assert allowed is False


def test_admin_permissions():
    rbac = RBACManager()

    for table in ["users", "accounts", "transactions"]:
        for action in ["SELECT", "INSERT", "UPDATE", "DELETE", "DDL:DROP"]:
            allowed, _ = rbac.check_authorization("admin", action, [table])
            assert allowed is True
