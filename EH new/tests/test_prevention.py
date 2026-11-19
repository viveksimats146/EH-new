from backend.prevention import PreventionEngine

def test_prevention_allow():
    res = PreventionEngine.evaluate_prevention("NORMAL", "ALLOW")
    assert res["action"] == "ALLOWED"
    assert res["can_execute"] is True

def test_prevention_warning():
    res = PreventionEngine.evaluate_prevention("MAY BE SQL INJECTION", "REVIEW")
    assert res["action"] == "WARNING"
    assert res["can_execute"] is True

def test_prevention_block():
    res = PreventionEngine.evaluate_prevention("SQL INJECTION", "BLOCK")
    assert res["action"] == "BLOCKED"
    assert res["can_execute"] is False
    assert res["status_code"] == 403
