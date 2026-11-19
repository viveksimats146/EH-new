import pytest
from backend.database import Base, engine, SessionLocal
from backend.models import QueryLog
from seed_demo import seed_demo_data

@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)

def test_query_log_persistence():
    db = SessionLocal()
    try:
        log = QueryLog(
            query_text="SELECT * FROM test",
            classification="NORMAL",
            risk_score=5,
            decision="ALLOW",
            detected_patterns="[]",
            execution_status="ALLOWED"
        )
        db.add(log)
        db.commit()

        retrieved = db.query(QueryLog).filter(QueryLog.id == log.id).first()
        assert retrieved is not None
        assert retrieved.query_text == "SELECT * FROM test"
        assert retrieved.classification == "NORMAL"
    finally:
        db.close()

def test_seed_demo_data():
    db = SessionLocal()
    try:
        res = seed_demo_data(db_session=db)
        assert res["status"] == "success"
        count = db.query(QueryLog).count()
        assert count > 0
    finally:
        db.close()
