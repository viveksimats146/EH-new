import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# Database configuration
DATABASE_PATH = os.getenv("DATABASE_PATH", str(BASE_DIR / "sql_injection.db"))
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DATABASE_PATH}"

# Classification Thresholds
# Risk Score 0 - 29: NORMAL
# Risk Score 30 - 59: MAY BE SQL INJECTION
# Risk Score 60 - 100: SQL INJECTION
NORMAL_THRESHOLD_MAX = 29
MAYBE_THRESHOLD_MAX = 59
SQLI_THRESHOLD_MIN = 60

# Model Paths
MODEL_DIR = BASE_DIR / "models"
MODEL_FILE_PATH = MODEL_DIR / "trained_model.pkl"
VECTORIZER_FILE_PATH = MODEL_DIR / "vectorizer.pkl"
DATASET_DIR = BASE_DIR / "dataset"
NORMAL_CSV = DATASET_DIR / "normal_queries.csv"
SQLI_CSV = DATASET_DIR / "sql_injection_queries.csv"

# Log directory
LOG_DIR = BASE_DIR / "outputs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
SECURITY_LOG_FILE = LOG_DIR / "security.log"
