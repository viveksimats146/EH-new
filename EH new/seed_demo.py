import json
from datetime import datetime, timedelta, timezone
import random
from backend.database import SessionLocal, init_db
from backend.models import QueryLog

DEMO_QUERIES = [
    # Normal Queries
    ("SELECT * FROM products WHERE category = 'books'", "NORMAL", 8, "ALLOW", [], "ALLOWED"),
    ("SELECT name, price FROM items WHERE id = 42", "NORMAL", 5, "ALLOW", [], "ALLOWED"),
    ("SELECT user_id, email FROM users WHERE status = 'active'", "NORMAL", 12, "ALLOW", [], "ALLOWED"),
    ("john_doe_99", "NORMAL", 0, "ALLOW", [], "ALLOWED"),
    ("laptop stand ergonomic adjustable", "NORMAL", 0, "ALLOW", [], "ALLOWED"),
    ("SELECT count(*) FROM orders WHERE user_id = 10", "NORMAL", 10, "ALLOW", [], "ALLOWED"),
    ("INSERT INTO comments (author, body) VALUES ('Alice', 'Great article!')", "NORMAL", 15, "ALLOW", [], "ALLOWED"),
    ("UPDATE profile SET bio = 'Software engineer' WHERE id = 3", "NORMAL", 14, "ALLOW", [], "ALLOWED"),
    ("SELECT title FROM posts ORDER BY created_at DESC LIMIT 10", "NORMAL", 9, "ALLOW", [], "ALLOWED"),
    ("SELECT * FROM inventory WHERE stock > 0 AND price < 50", "NORMAL", 11, "ALLOW", [], "ALLOWED"),

    # May Be SQL Injection Queries (Suspicious)
    ("' AND 1=1", "MAY BE SQL INJECTION", 45, "REVIEW", ["Boolean-based comparison (e.g., AND 1=2 or OR 1>0)", "Unbalanced single quote indicator"], "WARNING"),
    ("' OR 1=1", "MAY BE SQL INJECTION", 52, "REVIEW", ["OR tautology (e.g., OR 1=1 or OR 'a'='a')", "Unbalanced single quote indicator"], "WARNING"),
    ("SELECT * FROM users WHERE name = '' OR ''=''", "MAY BE SQL INJECTION", 48, "REVIEW", ["Quote wrapped logical operator"], "WARNING"),
    ("admin' AND '1'='1", "MAY BE SQL INJECTION", 55, "REVIEW", ["AND tautology (e.g., AND 1=1 or AND 'a'='a')"], "WARNING"),
    ("SELECT * FROM products WHERE id = 1 ORDER BY 5", "MAY BE SQL INJECTION", 35, "REVIEW", ["ORDER BY / GROUP BY numeric column enumeration"], "WARNING"),

    # High Confidence SQL Injection Attacks
    ("' OR '1'='1' --", "SQL INJECTION", 95, "BLOCK", ["OR tautology (e.g., OR 1=1 or OR 'a'='a')", "SQL comment indicator (-- or #)"], "BLOCKED"),
    ("admin'--", "SQL INJECTION", 85, "BLOCK", ["Quote breakout followed immediately by comment (e.g. admin'--)", "SQL comment indicator (-- or #)"], "BLOCKED"),
    ("' UNION SELECT username, password FROM users --", "SQL INJECTION", 98, "BLOCK", ["UNION-based SELECT injection", "SQL comment indicator (-- or #)"], "BLOCKED"),
    ("1; DROP TABLE users; --", "SQL INJECTION", 100, "BLOCK", ["Destructive SQL command execution (Stacked query)", "SQL comment indicator (-- or #)"], "BLOCKED"),
    ("' OR SLEEP(5) --", "SQL INJECTION", 92, "BLOCK", ["Time-based blind injection function (SLEEP/BENCHMARK)", "SQL comment indicator (-- or #)"], "BLOCKED"),
    ("1' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION())) --", "SQL INJECTION", 96, "BLOCK", ["Error-based XML SQL injection function", "SQL comment indicator (-- or #)"], "BLOCKED"),
    ("' UNION SELECT null, version(), database() --", "SQL INJECTION", 94, "BLOCK", ["UNION-based SELECT injection", "Database system metadata function"], "BLOCKED"),
]

def seed_demo_data(db_session=None):
    """Populates SQLite database with initial demo data."""
    close_at_end = False
    if db_session is None:
        init_db()
        db_session = SessionLocal()
        close_at_end = True

    try:
        # Check if DB already has records
        existing_count = db_session.query(QueryLog).count()
        if existing_count > 0:
            return {"status": "skipped", "message": f"Database already contains {existing_count} records."}

        now = datetime.now(timezone.utc)
        records_added = 0
        for i, (qtext, classification, risk, decision, patterns, status) in enumerate(DEMO_QUERIES):
            # Spread timestamps over past 24 hours
            time_offset = timedelta(minutes=random.randint(5, 1440))
            ts = now - time_offset

            log_item = QueryLog(
                query_text=qtext,
                classification=classification,
                risk_score=risk,
                decision=decision,
                detected_patterns=json.dumps(patterns),
                detection_method="LOCAL_HYBRID_ENGINE",
                timestamp=ts,
                execution_status=status
            )
            db_session.add(log_item)
            records_added += 1

        db_session.commit()
        return {"status": "success", "records_added": records_added}
    finally:
        if close_at_end:
            db_session.close()

if __name__ == "__main__":
    result = seed_demo_data()
    print("Seed Demo Data Result:", result)
