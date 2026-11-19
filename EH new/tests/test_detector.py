import pytest
from backend.rule_detector import RuleDetector
from backend.risk_scoring import RiskScorer
from backend.detection_engine import SQLiDetectionEngine

def test_normalization():
    detector = RuleDetector()
    raw = "%27%20OR%20%271%27%3D%271"
    normalized = detector.normalize_input(raw)
    assert "'" in normalized
    assert "OR" in normalized

def test_normal_queries():
    engine = SQLiDetectionEngine()
    safe_inputs = [
        "SELECT name FROM products WHERE id = 5",
        "john.doe@example.com",
        "hello world search string",
        "SELECT * FROM users WHERE status = 'active'"
    ]
    for inp in safe_inputs:
        res = engine.analyze_query(inp)
        assert res["classification"] == "NORMAL"
        assert res["decision"] == "ALLOW"
        assert res["risk_score"] < 30

def test_maybe_sqli_queries():
    engine = SQLiDetectionEngine()
    suspicious_inputs = [
        "' AND 1=1",
        "' OR 1=1",
        "SELECT * FROM users WHERE name = '' OR ''=''",
        "admin' AND '1'='1"
    ]
    for inp in suspicious_inputs:
        res = engine.analyze_query(inp)
        assert res["classification"] in ["MAY BE SQL INJECTION", "SQL INJECTION"]
        assert res["risk_score"] >= 30

def test_high_confidence_sqli_attacks():
    engine = SQLiDetectionEngine()
    attacks = [
        "' OR '1'='1' --",
        "admin'--",
        "' UNION SELECT username, password FROM users --",
        "1; DROP TABLE users; --",
        "' OR SLEEP(5) --"
    ]
    for atk in attacks:
        res = engine.analyze_query(atk)
        assert res["classification"] == "SQL INJECTION"
        assert res["decision"] == "BLOCK"
        assert res["risk_score"] >= 60
        assert res["execution_status"] == "BLOCKED"
