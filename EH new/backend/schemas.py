from pydantic import BaseModel, ConfigDict
from typing import List, Optional
from datetime import datetime

class AnalyzeRequest(BaseModel):
    query: str

class AnalyzeResponse(BaseModel):
    query_id: Optional[int] = None
    query: str
    classification: str
    risk_score: int
    decision: str
    risk_level: str
    detected_patterns: List[str]
    detection_method: str
    execution_status: str
    message: str

class QueryLogItem(BaseModel):
    id: int
    query_text: str
    classification: str
    risk_score: int
    decision: str
    detected_patterns: List[str]
    detection_method: str
    timestamp: str
    execution_status: str

    model_config = ConfigDict(from_attributes=True)

class StatisticsResponse(BaseModel):
    total_queries: int
    normal_count: int
    maybe_count: int
    sqli_count: int
    blocked_count: int
    detection_rate_pct: float
    sqli_percentage: float

class RecentActivityItem(BaseModel):
    id: int
    time: str
    classification: str
    decision: str
    risk_score: int
