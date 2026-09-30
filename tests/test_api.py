"""
API Endpoint Integration Tests
"""

from fastapi.testclient import TestClient
from src.vault_db.api.app import app

client = TestClient(app)


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
        json={
            "user": "alice@bank.com",
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
        json={
            "user": "alice@bank.com",
            "query": "DROP TABLE app_data.accounts;"
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "DENIED"
    assert "Access Denied" in data["error"]


def test_get_logs_endpoint():
    response = client.get("/api/logs?limit=5")
    assert response.status_code == 200
    logs = response.json()
    assert isinstance(logs, list)
    assert len(logs) > 0


def test_verify_log_endpoint():
    # Fetch latest log id
    logs_res = client.get("/api/logs?limit=1")
    log_id = logs_res.json()[0]["id"]

    verify_res = client.get(f"/api/verify/{log_id}")
    assert verify_res.status_code == 200
    vdata = verify_res.json()
    assert vdata["verified"] is True
    assert vdata["tamper_detected"] is False
