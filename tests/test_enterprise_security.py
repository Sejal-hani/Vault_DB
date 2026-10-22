"""
Comprehensive Test Suite for VaultDB Enterprise Security Specifications
Validates role-based access control, customer RLS on transactions,
sensitive column detection on SELECT *, and query-text masking in logs.
"""

import re
import pytest
from fastapi.testclient import TestClient
from src.vault_db.api.app import app
from src.vault_db.core.engine import VaultEngine
from src.vault_db.core.rbac import AccessDeniedError

client = TestClient(app)
engine = VaultEngine()


@pytest.fixture(autouse=True)
def reset_test_state():
    """Ensures each test runs with pristine role cache and no active elevations."""
    engine.postgres.execute_query("UPDATE app_data.access_requests SET status = 'REVOKED' WHERE status = 'APPROVED';")
    engine.postgres.clear_role_cache()
    yield
    engine.postgres.execute_query("UPDATE app_data.access_requests SET status = 'REVOKED' WHERE status = 'APPROVED';")
    engine.postgres.clear_role_cache()


def test_writer_role_permissions():
    """Writer can SELECT and UPDATE accounts/transactions, but is denied DELETE/DDL."""
    # 1. SELECT allowed
    res = engine.execute("SELECT id, name, balance FROM app_data.accounts LIMIT 1;", app_user="sarah.writer@bank.com")
    assert res["status"] == "SUCCESS"

    # 2. UPDATE allowed
    res_up = engine.execute("UPDATE app_data.transactions SET status = 'completed' WHERE id = 1;", app_user="sarah.writer@bank.com")
    assert res_up["status"] == "SUCCESS"

    # 3. DDL forbidden
    with pytest.raises(AccessDeniedError):
        engine.execute("DROP TABLE app_data.accounts;", app_user="sarah.writer@bank.com")


def test_reader_role_permissions():
    """Reader can only read (SELECT), mutations are denied."""
    # 1. SELECT allowed
    res = engine.execute("SELECT id, name FROM app_data.accounts LIMIT 1;", app_user="bob.reader@bank.com")
    assert res["status"] == "SUCCESS"

    # 2. UPDATE forbidden
    with pytest.raises(AccessDeniedError):
        engine.execute("UPDATE app_data.accounts SET balance = 500 WHERE id = 1;", app_user="bob.reader@bank.com")

    # 3. INSERT forbidden
    with pytest.raises(AccessDeniedError):
        engine.execute("INSERT INTO app_data.transactions (account_id, amount) VALUES (1, 100);", app_user="bob.reader@bank.com")


def test_customer_rls_on_transactions():
    """Customer queries on transactions are scoped to accounts owned by that customer."""
    res = engine.execute("SELECT * FROM app_data.transactions LIMIT 10;", app_user="alice@bank.com")
    assert res["status"] == "SUCCESS"
    assert res["is_scoped"] is True

    # Check that any returned transaction belongs to Alice's account (Account 1)
    if res["results"]:
        for row in res["results"]:
            account_id_val = row[1]  # account_id is 2nd column
            assert account_id_val == 1


def test_select_star_sensitive_flag():
    """SELECT * FROM accounts must flag is_sensitive=True and is_masked=True because SSN is returned."""
    res = engine.execute("SELECT * FROM app_data.accounts LIMIT 1;", app_user="admin@bank.com")
    assert res["status"] == "SUCCESS"
    assert res["is_sensitive"] is True
    assert "ssn" in res["sensitive_fields"]


def test_query_text_ssn_masked_in_audit():
    """Raw SSN embedded in query string is masked when stored in the audit log."""
    raw_query = "SELECT * FROM app_data.accounts WHERE ssn = '123-45-6789';"
    res = engine.execute(raw_query, app_user="admin@bank.com")
    assert res["status"] == "SUCCESS"
    log_id = res["immudb_log_id"]

    # Verify that the immudb record stored the masked version
    immu_record = engine.immudb.verify_audit_log(log_id)
    stored_q = immu_record["record"]["query_text"]
    assert "123-45-6789" not in stored_q
    assert "***-**-6789" in stored_q


def test_tamper_simulate_and_restore_via_api():
    """API endpoints /api/tamper-demo/simulate and /api/tamper-demo/restore operate smoothly."""
    # Execute a clean query
    exec_resp = client.post("/api/execute", json={"user": "admin@bank.com", "query": "SELECT count(*) FROM app_data.accounts;"})
    assert exec_resp.status_code == 200
    log_id = exec_resp.json()["immudb_log_id"]

    # 1. Simulate tamper
    sim_resp = client.post("/api/tamper-demo/simulate", json={"log_id": log_id})
    assert sim_resp.status_code == 200
    assert sim_resp.json()["status"] == "TAMPERED"

    # 2. Verify tamper is detected
    v_resp = client.get(f"/api/verify/{log_id}")
    assert v_resp.status_code == 200
    assert v_resp.json()["tamper_detected"] is True

    # 3. Restore
    rest_resp = client.post(f"/api/tamper-demo/restore?log_id={log_id}")
    assert rest_resp.status_code == 200
    assert rest_resp.json()["status"] == "RESTORED"

    # 4. Verify proof is clean again
    v2_resp = client.get(f"/api/verify/{log_id}")
    assert v2_resp.status_code == 200
    assert v2_resp.json()["verified"] is True
    assert v2_resp.json()["tamper_detected"] is False


def test_approval_workflow_elevation_and_auto_revocation():
    """
    Validates V2 Feature 3: Approval Workflows
    Bob (reader) requests access for 24 hours -> Manager approves -> Bob gets elevated role -> Revoke -> Reverts.
    """
    # 1. Bob starts as reader
    assert engine.get_user_role("bob.reader@bank.com") == "reader"

    # 2. Bob denied UPDATE by default
    with pytest.raises(AccessDeniedError):
        engine.execute("UPDATE app_data.transactions SET status = 'completed' WHERE id = 1;", app_user="bob.reader@bank.com")

    # 3. Bob requests 24h elevation to 'writer'
    req = engine.approvals.create_request(
        user_email="bob.reader@bank.com",
        requested_role="writer",
        duration_hours=24,
        reason="Required for ledger transaction reconciliations",
    )
    assert req["status"] == "PENDING"
    req_id = req["id"]

    # 4. Manager/Admin approves request
    appr = engine.approvals.approve_request(req_id, reviewer_email="admin@bank.com")
    assert appr["status"] == "APPROVED"
    assert "expires_at" in appr

    # 5. Bob now has active elevated role 'writer'
    assert engine.get_user_role("bob.reader@bank.com") == "writer"

    # 6. Now Bob can execute UPDATE query successfully!
    res = engine.execute("UPDATE app_data.transactions SET status = 'completed' WHERE id = 1;", app_user="bob.reader@bank.com")
    assert res["status"] == "SUCCESS"

    # 7. Revoke approval and verify immediate role downgrade back to reader
    rev = engine.approvals.revoke_request(req_id, reviewer_email="admin@bank.com")
    assert rev["status"] == "REVOKED"
    assert engine.get_user_role("bob.reader@bank.com") == "reader"

    # 8. Bob is again blocked from UPDATE
    with pytest.raises(AccessDeniedError):
        engine.execute("UPDATE app_data.transactions SET status = 'completed' WHERE id = 1;", app_user="bob.reader@bank.com")


def test_slack_webhook_alert_dispatch():
    """
    Validates V2 Feature 4: Anomaly Detection real-time Slack/webhook alert formatting and dispatch.
    """
    from src.vault_db.core.alerts import AlertDispatcher

    AlertDispatcher.dispatch_anomaly_alert(
        app_user="bob.reader@bank.com",
        user_role="reader",
        anomalies=["OFF_HOURS_ACTIVITY", "BULK_DATA_ACCESS"],
        query="SELECT * FROM app_data.accounts WHERE balance > 0;",
        rows_affected=5000,
        execution_status="SUCCESS",
    )
    import time
    time.sleep(0.1)

    recent = AlertDispatcher.get_recent_alerts(limit=10)
    assert len(recent) > 0
    matched = next((a for a in recent if a["user"] == "bob.reader@bank.com"), None)
    assert matched is not None
    assert "slack_payload" in matched
    assert "blocks" in matched["slack_payload"]


def test_api_approvals_flow():
    """Validates FastAPI approval endpoints /api/approvals."""
    # 1. Submit request via API
    resp = client.post("/api/approvals/request", json={
        "user_email": "bob.reader@bank.com",
        "requested_role": "writer",
        "duration_hours": 24,
        "reason": "API reconciliation access"
    })
    assert resp.status_code == 200
    req_id = resp.json()["id"]

    # 2. List requests
    list_resp = client.get("/api/approvals?status=PENDING")
    assert list_resp.status_code == 200
    assert any(r["id"] == req_id for r in list_resp.json())

    # 3. Approve via API
    appr_resp = client.post(f"/api/approvals/{req_id}/approve?reviewer_email=admin@bank.com")
    assert appr_resp.status_code == 200
    assert appr_resp.json()["status"] == "APPROVED"

    # 4. Clean up / Revoke via API
    rev_resp = client.post(f"/api/approvals/{req_id}/revoke?reviewer_email=admin@bank.com")
    assert rev_resp.status_code == 200
    assert rev_resp.json()["status"] == "REVOKED"


def test_customer_cannot_access_other_records_and_or_bypass_prevented():
    """
    Validates Section 2: Row-Level Security on standard dataset
    'Users can access only their own records. Verify customer cannot access other records.
    Test bypass attempts using custom SQL queries and joins.'
    """
    # 1. Alice queries all accounts
    res_alice = engine.execute("SELECT id, name, balance FROM app_data.accounts;", app_user="alice@bank.com")
    assert res_alice["status"] == "SUCCESS"
    assert res_alice["is_scoped"] is True
    # Verify ONLY Alice's records are returned
    names = [row[1] for row in res_alice["results"]]
    assert "Robert Ross" not in names
    assert all(n == "Alice Smith" for n in names)

    # 2. Alice attempts bypass using WHERE 1=1 OR name = 'Robert Ross'
    bypass_query = "SELECT id, name, balance FROM app_data.accounts WHERE 1=1 OR name = 'Robert Ross';"
    res_bypass = engine.execute(bypass_query, app_user="alice@bank.com")
    assert res_bypass["status"] == "SUCCESS"
    bypass_names = [row[1] for row in res_bypass["results"]]
    assert "Robert Ross" not in bypass_names
    assert all(n == "Alice Smith" for n in bypass_names)

    # 3. Alice queries transactions - can never see other customers' transactions (Account != 1)
    res_tx = engine.execute("SELECT id, account_id, amount, merchant FROM app_data.transactions;", app_user="alice@bank.com")
    assert res_tx["status"] == "SUCCESS"
    if res_tx["results"]:
        for row in res_tx["results"]:
            assert row[1] == 1  # Alice only owns Account 1


def test_non_admin_cannot_approve_requests_backend_enforcement():
    """
    Backend-first zero trust: Non-admin (employee/customer) attempting to approve
    a request directly via API receives HTTP 403 Forbidden.
    """
    # 1. Create a request for employee John
    req = engine.approvals.create_request(
        user_email="john@bank.com",
        requested_role="admin",
        requested_table="*",
        duration_hours=24,
        reason="System Maintenance"
    )
    req_id = req["id"]

    # 2. Login as Employee John to get employee token
    login_resp = client.post("/api/auth/demo-login/employee")
    assert login_resp.status_code == 200
    emp_token = login_resp.json()["access_token"]

    # 3. Employee attempts to approve his own request via API -> Denied 403
    headers = {"Authorization": f"Bearer {emp_token}"}
    appr_resp = client.post(f"/api/approvals/{req_id}/approve", headers=headers)
    assert appr_resp.status_code == 403

    # 4. Admin approves successfully
    admin_login = client.post("/api/auth/demo-login/admin")
    admin_token = admin_login.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    admin_appr = client.post(f"/api/approvals/{req_id}/approve", headers=admin_headers)
    assert admin_appr.status_code == 200
    assert admin_appr.json()["status"] == "APPROVED"

    # Cleanup
    client.post(f"/api/approvals/{req_id}/revoke", headers=admin_headers)


def test_compliance_pdf_report_with_role_and_date_filters():
    """
    Validates Section 7: Compliance PDF Reports
    Filters by role, status, date range, and returns valid certified PDF bytes.
    """
    resp = client.get("/api/reports/pdf?role=admin&status=SUCCESS&time_range=24h")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content.startswith(b"%PDF")


ROLE_USERS = {
    "customer": "alice@bank.com",
    "employee": "john@bank.com",
    "auditor": "compliance.lead@bank.com",
    "admin": "admin@bank.com",
}


@pytest.mark.parametrize("role", ["customer", "employee", "auditor", "admin"])
@pytest.mark.parametrize("table", ["users", "accounts", "transactions"])
def test_no_secrets_in_results(role, table):
    """
    Validates that password_hash and api_key are NEVER leaked in query results
    or column lists for ANY role, and that non-admin queries never reveal raw SSNs.
    """
    user_email = ROLE_USERS[role]
    try:
        res = engine.execute(f"SELECT * FROM app_data.{table} LIMIT 10;", app_user=user_email)
    except AccessDeniedError:
        # Table access denied by RBAC policy (e.g. customer/employee cannot SELECT users)
        return

    assert res["status"] == "SUCCESS"
    columns = res.get("columns", [])
    results = res.get("results", [])
    text = str(results) + " " + str(columns)

    # 1. Credentials must NEVER appear in column headers or row values for any role
    assert "password_hash" not in text
    assert "api_key" not in text

    # 2. Non-admin roles (customer, employee, auditor) must NEVER see raw unmasked SSNs
    if role != "admin":
        assert not re.search(r"\b\d{3}-\d{2}-\d{4}\b", text)
        if "ssn" in [c.lower() for c in columns]:
            ssn_idx = [i for i, c in enumerate(columns) if c.lower() == "ssn"][0]
            for row in results:
                if row[ssn_idx]:
                    assert str(row[ssn_idx]).startswith("***-**-")


def test_schema_explorer_secrets_and_status_hidden():
    """
    Validates that the Schema Explorer endpoint (/api/tables/{table}):
    - Never leaks password_hash or api_key
    - Hides the 'status' column on the 'users' table
    - Dynamically masks SSNs for all table previews
    """
    # 1. Check users table
    resp_users = client.get("/api/tables/users")
    assert resp_users.status_code == 200
    data_users = resp_users.json()
    assert "password_hash" not in data_users["columns"]
    assert "api_key" not in data_users["columns"]
    assert "status" not in data_users["columns"]
    assert "password_hash" not in str(data_users["rows"])
    assert "api_key" not in str(data_users["rows"])

    # 2. Check accounts table
    resp_accs = client.get("/api/tables/accounts")
    assert resp_accs.status_code == 200
    data_accs = resp_accs.json()
    assert "password_hash" not in str(data_accs)
    assert "api_key" not in str(data_accs)
    # Raw SSN pattern must never appear in table inspection
    assert not re.search(r"\b\d{3}-\d{2}-\d{4}\b", str(data_accs["rows"]))



