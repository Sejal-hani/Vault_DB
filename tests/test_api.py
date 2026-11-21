"""
API Endpoint Integration Tests
"""

from fastapi.testclient import TestClient
from src.vault_db.api.app import app
from src.vault_db.auth.jwt_handler import create_access_token

client = TestClient(app)


def get_auth_headers(email: str = "admin@bank.com", role: str = "admin") -> dict:
    """Helper creating valid JWT authorization headers for testing."""
    token = create_access_token({"sub": email, "role": role})
    return {"Authorization": f"Bearer {token}"}


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["postgres"] == "healthy"
    assert data["immudb"] == "healthy"


def test_ledger_state_endpoint():
    response = client.get("/api/ledger-state")
    assert response.status_code == 200
    data = response.json()
    assert "root_hash" in data
    assert data["tx_id"] > 0


def test_execute_query_authorized():
    response = client.post(
        "/api/execute",
        headers=get_auth_headers("alice@bank.com", "customer"),
        json={
            "query": "SELECT * FROM app_data.accounts;"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert data["immudb_verified"] is True
    assert data["immudb_tx_id"] is not None


def test_execute_query_denied():
    response = client.post(
        "/api/execute",
        headers=get_auth_headers("alice@bank.com", "customer"),
        json={
            "query": "DROP TABLE app_data.accounts;"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "DENIED"
    assert "Access Denied" in data["error"]


def test_execute_query_unauthenticated_rejected():
    """Unauthenticated query execution must be rejected with 401 Unauthorized."""
    response = client.post(
        "/api/execute",
        json={
            "user": "admin@bank.com",
            "query": "SELECT * FROM app_data.accounts;"
        }
    )
    assert response.status_code == 401
    assert "Authentication required" in response.json()["detail"]


def test_execute_query_ignores_client_supplied_user_spoofing():
    """
    Even if client specifies 'user': 'admin@bank.com' in JSON payload,
    server must strictly use authenticated identity (alice@bank.com, customer)
    and deny unauthorized DROP statements.
    """
    alice_headers = get_auth_headers("alice@bank.com", "customer")
    response = client.post(
        "/api/execute",
        headers=alice_headers,
        json={
            "user": "admin@bank.com",
            "query": "DROP TABLE app_data.accounts;"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "DENIED"
    assert "Access Denied" in data["error"]


def test_get_logs_endpoint():
    response = client.get("/api/logs?limit=5", headers=get_auth_headers("admin@bank.com", "admin"))
    assert response.status_code == 200
    logs = response.json()
    assert isinstance(logs, list)
    assert len(logs) > 0


def test_get_logs_unauthenticated_rejected():
    """Unauthenticated audit log requests must be rejected with 401 Unauthorized."""
    response = client.get("/api/logs?limit=5")
    assert response.status_code == 401


def test_customer_logs_scoped_to_own_records():
    """Customers requesting /api/logs are strictly scoped to their own activity."""
    response = client.get(
        "/api/logs?limit=20",
        headers=get_auth_headers("alice@bank.com", "customer")
    )
    assert response.status_code == 200
    logs = response.json()
    for entry in logs:
        assert entry["user"] == "alice@bank.com"


def test_verify_log_endpoint():
    # Execute query to create synchronized test record across immudb and PostgreSQL
    admin_headers = get_auth_headers("admin@bank.com", "admin")
    exec_res = client.post(
        "/api/execute",
        headers=admin_headers,
        json={
            "query": "SELECT account_number FROM app_data.accounts LIMIT 1;"
        }
    )
    assert exec_res.status_code == 200
    log_id = exec_res.json()["immudb_log_id"]

    verify_res = client.get(f"/api/verify/{log_id}", headers=admin_headers)
    assert verify_res.status_code == 200
    vdata = verify_res.json()
    assert vdata["verified"] is True
    assert vdata["tamper_detected"] is False


def test_table_pagination_endpoint():
    response = client.get("/api/tables/accounts?limit=2&page=1", headers=get_auth_headers("admin@bank.com", "admin"))
    assert response.status_code == 200
    data = response.json()
    assert data["table"] == "accounts"
    assert "total_count" in data
    assert data["page"] == 1
    assert data["limit"] == 2
    assert "total_pages" in data
    assert len(data["rows"]) <= 2


def test_tables_endpoint_forbidden_for_customer():
    """Customers are forbidden from inspecting database schema tables."""
    response = client.get("/api/tables", headers=get_auth_headers("alice@bank.com", "customer"))
    assert response.status_code == 403


def test_get_logs_with_filters():
    response = client.get("/api/logs?limit=10&time_range=7d&status=SUCCESS", headers=get_auth_headers("admin@bank.com", "admin"))
    assert response.status_code == 200
    logs = response.json()
    assert isinstance(logs, list)


def test_export_pdf_endpoint():
    response = client.get("/api/reports/pdf?table=accounts&limit=10", headers=get_auth_headers("admin@bank.com", "admin"))
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert len(response.content) > 1000
