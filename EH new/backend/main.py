import json
from fastapi import FastAPI, Depends, HTTPException, Query, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, or_
from typing import Optional, List
from datetime import datetime, timedelta, timezone

from backend.database import get_db, init_db
from backend.models import QueryLog
from backend.schemas import (
    AnalyzeRequest, AnalyzeResponse, StatisticsResponse,
    QueryLogItem, RecentActivityItem
)
from backend.detection_engine import SQLiDetectionEngine
from backend.logger import log_security_event
from seed_demo import seed_demo_data
from backend import config

# Initialize FastAPI Application
app = FastAPI(
    title="Automated SQL Injection Detection and Prevention System",
    description="100% Local Rule-Based and Machine Learning SQLi Detection System",
    version="1.0.0"
)

# Initialize Database tables on startup
@app.on_event("startup")
def on_startup():
    init_db()

# Initialize Detection Engine singleton
detection_engine = SQLiDetectionEngine()

# Mount Static Assets and Jinja2 Templates
STATIC_DIR = config.BASE_DIR / "frontend" / "static"
TEMPLATES_DIR = config.BASE_DIR / "frontend" / "templates"

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# ========================================================
# HTML PAGE ROUTES
# ========================================================

@app.get("/", response_class=HTMLResponse)
def read_analyzer_page(request: Request):
    """PAGE 1: HOME / QUERY ANALYZER"""
    return templates.TemplateResponse(
        request=request, name="index.html", context={"active_page": "analyzer"}
    )

@app.get("/dashboard", response_class=HTMLResponse)
def read_dashboard_page(request: Request):
    """PAGE 2: SECURITY DASHBOARD"""
    return templates.TemplateResponse(
        request=request, name="dashboard.html", context={"active_page": "dashboard"}
    )

@app.get("/injections", response_class=HTMLResponse)
def read_injections_page(request: Request):
    """PAGE 3: SQL INJECTION HISTORY"""
    return templates.TemplateResponse(
        request=request, name="injections.html", context={"active_page": "injections"}
    )

@app.get("/query/{query_id}", response_class=HTMLResponse)
def read_query_details_page(request: Request, query_id: int):
    """PAGE 4: QUERY DETAILS PAGE"""
    return templates.TemplateResponse(
        request=request,
        name="query_details.html",
        context={"query_id": query_id, "active_page": "analyzer"}
    )

# ========================================================
# REST API ENDPOINTS
# ========================================================

@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze_query_endpoint(payload: AnalyzeRequest, db: Session = Depends(get_db)):
    """
    POST /api/analyze
    Analyzes raw input string using local rule engine + local ML model.
    Stores result into SQLite database and returns detailed risk analysis.
    """
    query_text = payload.query.strip() if payload.query else ""
    if not query_text:
        raise HTTPException(
            status_code=400,
            detail="Please enter a query or input for analysis."
        )

    # 1. Run local detection engine pipeline
    result = detection_engine.analyze_query(query_text)

    # 2. Store result in SQLite database
    patterns_json = json.dumps(result["detected_patterns"])
    query_log = QueryLog(
        query_text=query_text,
        classification=result["classification"],
        risk_score=result["risk_score"],
        decision=result["decision"],
        detected_patterns=patterns_json,
        detection_method=result["detection_method"],
        timestamp=datetime.now(timezone.utc),
        execution_status=result["execution_status"]
    )
    db.add(query_log)
    db.commit()
    db.refresh(query_log)

    # 3. Log security event to file audit log
    log_security_event(
        query_id=query_log.id,
        classification=query_log.classification,
        risk_score=query_log.risk_score,
        decision=query_log.decision,
        patterns=result["detected_patterns"]
    )

    return AnalyzeResponse(
        query_id=query_log.id,
        query=query_text,
        classification=result["classification"],
        risk_score=result["risk_score"],
        decision=result["decision"],
        risk_level=result["risk_level"],
        detected_patterns=result["detected_patterns"],
        detection_method=result["detection_method"],
        execution_status=result["execution_status"],
        message=result["message"]
    )

@app.get("/api/statistics", response_model=StatisticsResponse)
def get_statistics_endpoint(db: Session = Depends(get_db)):
    """
    GET /api/statistics
    Calculates dynamic security counts, detection rate, and injection percentages from database records.
    Handles zero state safely without division-by-zero errors.
    """
    total_queries = db.query(QueryLog).count()
    normal_count = db.query(QueryLog).filter(QueryLog.classification == "NORMAL").count()
    maybe_count = db.query(QueryLog).filter(QueryLog.classification == "MAY BE SQL INJECTION").count()
    sqli_count = db.query(QueryLog).filter(QueryLog.classification == "SQL INJECTION").count()
    blocked_count = db.query(QueryLog).filter(QueryLog.decision == "BLOCK").count()

    if total_queries > 0:
        detection_rate_pct = round(((maybe_count + sqli_count) / total_queries) * 100.0, 1)
        sqli_percentage = round((sqli_count / total_queries) * 100.0, 1)
    else:
        detection_rate_pct = 0.0
        sqli_percentage = 0.0

    return StatisticsResponse(
        total_queries=total_queries,
        normal_count=normal_count,
        maybe_count=maybe_count,
        sqli_count=sqli_count,
        blocked_count=blocked_count,
        detection_rate_pct=detection_rate_pct,
        sqli_percentage=sqli_percentage
    )

@app.get("/api/injections")
def get_injections_endpoint(
    search: Optional[str] = Query(None),
    min_risk: Optional[int] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """
    GET /api/injections
    Retrieves records classified ONLY as 'SQL INJECTION'.
    Supports search query, risk score filtering, and pagination.
    """
    query = db.query(QueryLog).filter(QueryLog.classification == "SQL INJECTION")

    if search:
        search_pattern = f"%{search.strip()}%"
        query = query.filter(
            or_(
                QueryLog.query_text.ilike(search_pattern),
                QueryLog.detected_patterns.ilike(search_pattern)
            )
        )

    if min_risk is not None:
        query = query.filter(QueryLog.risk_score >= min_risk)

    total_records = query.count()
    offset = (page - 1) * limit
    records = query.order_by(desc(QueryLog.timestamp)).offset(offset).limit(limit).all()

    formatted_records = []
    for r in records:
        try:
            patterns = json.loads(r.detected_patterns) if r.detected_patterns else []
        except Exception:
            patterns = [r.detected_patterns] if r.detected_patterns else []

        formatted_records.append({
            "id": r.id,
            "query_text": r.query_text,
            "classification": r.classification,
            "risk_score": r.risk_score,
            "decision": r.decision,
            "detected_patterns": patterns,
            "detection_method": r.detection_method,
            "timestamp": r.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "execution_status": r.execution_status
        })

    return {
        "total": total_records,
        "page": page,
        "limit": limit,
        "total_pages": (total_records + limit - 1) // limit if total_records > 0 else 1,
        "data": formatted_records
    }

@app.get("/api/recent")
def get_recent_activity_endpoint(limit: int = Query(5, ge=1, le=20), db: Session = Depends(get_db)):
    """
    GET /api/recent
    Returns latest query analysis events for recent activity timeline feed.
    """
    logs = db.query(QueryLog).order_by(desc(QueryLog.timestamp)).limit(limit).all()
    recent = []
    for log in logs:
        time_str = log.timestamp.strftime("%I:%M %p")
        recent.append({
            "id": log.id,
            "time": time_str,
            "timestamp_iso": log.timestamp.isoformat(),
            "query_snippet": log.query_text[:40] + ("..." if len(log.query_text) > 40 else ""),
            "classification": log.classification,
            "decision": log.decision,
            "risk_score": log.risk_score
        })
    return {"recent_activity": recent}

@app.get("/api/chart-data")
def get_chart_data_endpoint(db: Session = Depends(get_db)):
    """
    GET /api/chart-data
    Returns dynamic data arrays for Chart.js pie/doughnut distribution and time-series line chart.
    """
    # Distribution counts
    normal_count = db.query(QueryLog).filter(QueryLog.classification == "NORMAL").count()
    maybe_count = db.query(QueryLog).filter(QueryLog.classification == "MAY BE SQL INJECTION").count()
    sqli_count = db.query(QueryLog).filter(QueryLog.classification == "SQL INJECTION").count()

    # Time series (grouped by date/hour)
    recent_logs = db.query(QueryLog).order_by(QueryLog.timestamp.asc()).all()
    time_series = {}
    for log in recent_logs:
        date_key = log.timestamp.strftime("%b %d %H:00")
        if date_key not in time_series:
            time_series[date_key] = {"normal": 0, "maybe": 0, "sqli": 0}
        if log.classification == "NORMAL":
            time_series[date_key]["normal"] += 1
        elif log.classification == "MAY BE SQL INJECTION":
            time_series[date_key]["maybe"] += 1
        elif log.classification == "SQL INJECTION":
            time_series[date_key]["sqli"] += 1

    labels = list(time_series.keys())
    sqli_series = [time_series[k]["sqli"] for k in labels]
    maybe_series = [time_series[k]["maybe"] for k in labels]
    normal_series = [time_series[k]["normal"] for k in labels]

    return {
        "distribution": {
            "labels": ["NORMAL", "MAY BE SQL INJECTION", "SQL INJECTION"],
            "counts": [normal_count, maybe_count, sqli_count]
        },
        "timeline": {
            "labels": labels,
            "sqli_series": sqli_series,
            "maybe_series": maybe_series,
            "normal_series": normal_series
        }
    }

@app.get("/api/query/{query_id}")
def get_query_detail_endpoint(query_id: int, db: Session = Depends(get_db)):
    """
    GET /api/query/{id}
    Retrieves full details for a specific query log record.
    """
    log = db.query(QueryLog).filter(QueryLog.id == query_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Query record not found")

    try:
        patterns = json.loads(log.detected_patterns) if log.detected_patterns else []
    except Exception:
        patterns = [log.detected_patterns] if log.detected_patterns else []

    return {
        "id": log.id,
        "query_text": log.query_text,
        "classification": log.classification,
        "risk_score": log.risk_score,
        "decision": log.decision,
        "detected_patterns": patterns,
        "detection_method": log.detection_method,
        "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "execution_status": log.execution_status
    }

@app.post("/api/demo-data")
def seed_demo_data_endpoint(db: Session = Depends(get_db)):
    """
    POST /api/demo-data
    Populates SQLite database with sample demonstration query logs locally.
    """
    res = seed_demo_data(db_session=db)
    return res
