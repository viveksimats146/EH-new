# Automated SQL Injection Detection and Prevention System

A fast, lightweight, 100% locally running cybersecurity application designed for real-time automated SQL Injection (SQLi) detection, risk scoring, three-way classification, attack prevention, and SOC security dashboard analytics.

---

## 🌟 Key Features

- **100% Local & Privacy-Preserving**: Runs entirely offline without requiring external AI APIs, internet access, or API keys. Zero dependency on third-party cloud services.
- **Three-Way Classification Engine**:
  - **NORMAL** (`0–29` Risk Score, Decision: `ALLOW`)
  - **MAY BE SQL INJECTION** (`30–59` Risk Score, Decision: `REVIEW`)
  - **SQL INJECTION** (`60–100` Risk Score, Decision: `BLOCK`)
- **Multi-Stage Detection Pipeline**:
  - **Input Normalizer**: Iterative URL decoding, whitespace normalization, comment stripping, hex/char unwrapping.
  - **Pattern Matching Rule Engine**: Detects OR/AND tautologies, UNION attacks, stacked queries, boolean comparisons, error-based XML functions, time-based delays, quote anomalies.
  - **Local ML Classifier**: Scikit-Learn TF-IDF vectorizer + Logistic Regression model trained on local dataset.
  - **Risk Scorer**: Weighted scoring capped at 100 with explainable pattern indicators.
- **Prevention Firewall**: Automatically blocks high-confidence attacks from reaching application database systems.
- **SOC Security Dashboard**:
  - Live metric counters (Total, Normal, May Be, SQL Injection, Blocked).
  - Standalone Chart.js Doughnut Chart (Classification Distribution).
  - Timeline Line Chart (Attack frequency over time).
  - Dynamic telemetry summary & recent activity feed.
- **SQL Injection History**:
  - Dedicated audit log filtering exclusively `SQL INJECTION` events.
  - Real-time search, risk threshold filters, and pagination.
- **Query Telemetry Details**:
  - In-depth forensic view of analyzed inputs, exact detected patterns, risk scores, and execution decisions.

---

## 🏗️ System Architecture

```
                    USER
                      |
                      v
              WEB APPLICATION
                      |
                      v
              QUERY ANALYZER
                      |
                      v
             INPUT NORMALIZER
                      |
                      v
             LOCAL DETECTION
                /          \
               /            \
        RULE ENGINE       ML ENGINE
               \            /
                \          /
                 v        v
                RISK SCORING
                      |
          +-----------+-----------+
          |           |           |
          v           v           v
       NORMAL      MAY BE      SQL INJECTION
          |        INJECTION         |
          v           |              v
        ALLOW       REVIEW         BLOCK
                      |
                      v
               SQLITE DATABASE
                      |
          +-----------+-----------+
          |           |           |
          v           v           v
      DASHBOARD   STATISTICS   HISTORY
          |
          v
      PIE / BAR / LINE CHARTS
```

---

## 🛠️ Technology Stack

- **Backend**: Python 3.10+, FastAPI, Uvicorn
- **Database**: SQLite, SQLAlchemy
- **Machine Learning**: Scikit-learn, Pandas, NumPy
- **Frontend**: HTML5, Jinja2 Templates, Custom Dark SOC CSS, JavaScript
- **Charts**: Local standalone Chart.js (Zero CDN runtime dependency)
- **Testing**: Pytest, HTTPX

---

## 📁 Project Structure

```
c:\Users\LENOVO\OneDrive\Desktop\EH new\
├── backend/
│   ├── main.py              # FastAPI app initialization, routes, static & template mounts
│   ├── database.py          # SQLAlchemy engine, SessionLocal, Base
│   ├── models.py            # DB models (QueryLog)
│   ├── schemas.py           # Pydantic schemas for requests & responses
│   ├── detection_engine.py  # Master detection orchestrator (Rule + ML blend)
│   ├── rule_detector.py     # Local rule-based pattern matching & normalization
│   ├── risk_scoring.py      # Weighted risk scoring engine & 3-way classification
│   ├── prevention.py        # Decision engine (ALLOW / REVIEW / BLOCK)
│   ├── logger.py            # Security audit logger
│   └── config.py            # Thresholds, paths, DB URI
├── frontend/
│   ├── templates/           # Jinja2 pages (index, dashboard, injections, query_details)
│   └── static/              # CSS, JS, vendor scripts
├── dataset/                 # Training datasets (normal_queries.csv, sql_injection_queries.csv)
├── models/                  # ML detector module & local trained pkl models
├── tests/                   # Pytest automated test suite
├── seed_demo.py             # Demo data population script
├── run.py                   # One-click startup script
└── requirements.txt         # Dependencies
```

---

## 🚀 Installation & Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start Application
```bash
python run.py
```

### 3. Open Web Interface
Open your browser and navigate to:
[http://127.0.0.1:8000](http://127.0.0.1:8000)

---

## 🧪 Running Automated Tests

To execute the unit and integration test suite:

```bash
pytest
```

---

## 🛡️ Security & Prevention Rules

| Risk Score Range | Classification | Security Decision | Prevention Action |
|---|---|---|---|
| `0 – 29` | **NORMAL** | `ALLOW` | Allowed for database execution |
| `30 – 59` | **MAY BE SQL INJECTION** | `REVIEW` | Flagged for security warning & review |
| `60 – 100` | **SQL INJECTION** | `BLOCK` | Blocked by firewall (execution prevented) |
