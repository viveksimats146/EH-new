import logging
from datetime import datetime
from backend import config

# Configure python logger for security audit
logger = logging.getLogger("security_logger")
logger.setLevel(logging.INFO)

# Create file handler for security log
file_handler = logging.FileHandler(config.SECURITY_LOG_FILE, encoding="utf-8")
formatter = logging.Formatter("[%(asctime)s] %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
file_handler.setFormatter(formatter)

if not logger.handlers:
    logger.addHandler(file_handler)

def log_security_event(query_id: int, classification: str, risk_score: int, decision: str, patterns: list):
    """
    Logs structured security audit record.
    Never stores sensitive passwords/credentials.
    """
    pattern_str = ", ".join(patterns) if patterns else "None"
    log_msg = (
        f"QueryID: {query_id} | Classification: {classification} | "
        f"RiskScore: {risk_score}/100 | Decision: {decision} | Patterns: [{pattern_str}]"
    )
    if classification == "SQL INJECTION":
        logger.warning(f"ATTACK DETECTED: {log_msg}")
    elif classification == "MAY BE SQL INJECTION":
        logger.info(f"SUSPICIOUS ACTIVITY: {log_msg}")
    else:
        logger.info(f"CLEAN QUERY: {log_msg}")
