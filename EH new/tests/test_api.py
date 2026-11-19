import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database import Base, engine, SessionLocal

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

def test_api_analyze_normal():
    response = client.post("/api/analyze", json={"query": "SELECT * FROM books WHERE id = 1"})
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "NORMAL"
    assert data["decision"] == "ALLOW"
    assert data["risk_score"] < 30

def test_api_analyze_sqli():
    response = client.post("/api/analyze", json={"query": "' OR '1'='1' --"})
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "SQL INJECTION"
    assert data["decision"] == "BLOCK"
    assert data["risk_score"] >= 60

def test_api_empty_query():
    response = client.post("/api/analyze", json={"query": ""})
    assert response.status_code == 400

def test_api_statistics():
    # Analyze 1 normal, 1 attack
    client.post("/api/analyze", json={"query": "SELECT * FROM books"})
    client.post("/api/analyze", json={"query": "' OR '1'='1' --"})

    stats_res = client.get("/api/statistics")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert stats["total_queries"] == 2
    assert stats["normal_count"] == 1
    assert stats["sqli_count"] == 1

def test_api_injections_history_filter():
    client.post("/api/analyze", json={"query": "SELECT * FROM normal_table"})
    client.post("/api/analyze", json={"query": "' OR '1'='1' --"})

    inj_res = client.get("/api/injections")
    assert inj_res.status_code == 200
    inj_data = inj_res.json()
    assert inj_data["total"] == 1
    assert inj_data["data"][0]["classification"] == "SQL INJECTION"
