from sqlalchemy import Column, Integer, String, Text, DateTime
from datetime import datetime, timezone
from backend.database import Base

class QueryLog(Base):
    """
    Query Audit Log table stored in SQLite database.
    Tracks query text, classification, risk score, decision, detected patterns, timestamp.
    """
    __tablename__ = "query_logs"

    id = Column(Integer, primary_key=True, index=True)
    query_text = Column(Text, nullable=False)
    classification = Column(String(50), nullable=False, index=True)  # NORMAL, MAY BE SQL INJECTION, SQL INJECTION
    risk_score = Column(Integer, nullable=False)
    decision = Column(String(20), nullable=False)  # ALLOW, REVIEW, BLOCK
    detected_patterns = Column(Text, nullable=True)  # Store JSON string or comma-separated patterns
    detection_method = Column(String(50), nullable=False, default="LOCAL_RULE_ENGINE")
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    execution_status = Column(String(50), nullable=False, default="ALLOWED")  # ALLOWED, WARNING, BLOCKED
