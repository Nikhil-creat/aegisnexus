import os
import tempfile

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

os.environ["DB_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
os.environ["ADMIN_PASSWORD"] = "test-admin-password"
os.environ["AUTH_REQUIRED"] = "true"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _login(client, user="admin", pw="test-admin-password"):
    r = client.post("/api/auth/login", json={"username": user, "password": pw})
    return r


@pytest.fixture(scope="module")
def H(client):
    return {"Authorization": "Bearer " + _login(client).json()["token"]}


def test_health_is_public(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["auth_required"] is True


def test_protected_routes_need_token(client):
    assert client.get("/api/cases").status_code == 401
    assert client.get("/api/cases", headers={"Authorization": "Bearer junk"}).status_code == 401


def test_login_failure(client):
    assert _login(client, pw="wrong").status_code == 401


def test_rag_search_and_validation(client, H):
    assert client.post("/api/rag/search", json={"query": "brute force ssh", "k": 3}, headers=H).json()["hits"]
    assert client.post("/api/rag/search", json={"query": "x"}, headers=H).status_code == 422


def test_full_case_workflow(client, H):
    alert = client.get("/api/demo/alerts", headers=H).json()[0]
    r = client.post("/api/investigate", json=alert, headers=H)
    assert r.status_code == 200
    case = r.json()
    assert case["report"]["risk_score"] >= 80 and case["case_id"]
    cid = case["case_id"]
    assert client.get(f"/api/cases/{cid}", headers=H).status_code == 200
    d = client.post(f"/api/cases/{cid}/actions/0", json={"decision": "approve"}, headers=H)
    assert d.status_code == 200 and d.json()["status"] == "approved"
    assert client.post(f"/api/cases/{cid}/actions/0", json={"decision": "reject"}, headers=H).status_code == 409
    assert client.get(f"/api/cases/{cid}", headers=H).json()["report"]["recommendations"][0]["status"] == "approved"
    assert client.get("/api/stats", headers=H).json()["cases"] >= 1
    assert any(e["event"] == "action_approve" for e in client.get("/api/audit", headers=H).json())


def test_roles_are_enforced(client, H):
    assert client.post("/api/users", json={"username": "vera", "password": "viewer-password-1", "role": "viewer"}, headers=H).status_code == 201
    vh = {"Authorization": "Bearer " + _login(client, "vera", "viewer-password-1").json()["token"]}
    assert client.get("/api/cases", headers=vh).status_code == 200            # viewers can read
    alert = client.get("/api/demo/alerts", headers=vh).json()[0]
    assert client.post("/api/investigate", json=alert, headers=vh).status_code == 403
    assert client.get("/api/audit", headers=vh).status_code == 403


def test_file_upload_and_limits(client, H):
    ok = client.post("/api/analyze/file", files={"file": ("a.bin", b"\x00" * 4096)}, headers=H)
    assert ok.status_code == 200 and "label" in ok.json()
    assert client.post("/api/analyze/file", files={"file": ("a.bin", b"")}, headers=H).status_code == 400


def test_bad_flow_rejected(client, H):
    assert client.post("/api/analyze/flow", json={"sequence": [[0, 0, 0, 0, 0]]}, headers=H).status_code == 422


def test_stream_and_report_and_dedupe(client, H):
    alert = client.get("/api/demo/alerts", headers=H).json()[3]
    with client.stream("POST", "/api/investigate/stream", json=alert, headers=H) as r:
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/event-stream")
        body = "".join(r.iter_text())
    assert body.count("event: step") >= 5 and "event: result" in body
    cid = client.get("/api/cases", headers=H).json()[0]["id"]
    md = client.get(f"/api/cases/{cid}/report.md", headers=H)
    assert md.status_code == 200 and md.text.startswith("# Incident report")
    again = client.post("/api/investigate", json=alert, headers=H).json()
    assert again["cached"] is True


def test_prometheus_endpoint(client):
    text = client.get("/metrics").text
    assert "aegis_http_requests_total" in text and "aegis_investigations_total" in text
