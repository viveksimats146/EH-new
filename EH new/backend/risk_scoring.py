from typing import Dict, Any, List
from backend import config

class RiskScorer:
    """
    Computes final risk score (capped at 100) and maps to 3-way classification:
    - NORMAL (0-29) -> ALLOW
    - MAY BE SQL INJECTION (30-59) -> REVIEW
    - SQL INJECTION (60-100) -> BLOCK
    """

    @staticmethod
    def calculate_score(rule_score: int, ml_probability: float = None) -> int:
        """
        Combines rule-based score and optional ML probability.
        If ML is available, rule score is augmented or weighted.
        Score is capped at 100.
        """
        base_score = float(rule_score)

        if ml_probability is not None:
            # ml_probability is between 0.0 and 1.0 (probability of SQLi)
            ml_component = ml_probability * 50.0  # contribute up to 50 points
            combined = (base_score * 0.6) + (ml_component * 0.8)
            final_score = int(round(combined))
        else:
            final_score = int(round(base_score))

        # Enforce boundary [0, 100]
        return min(max(final_score, 0), 100)

    @classmethod
    def classify(cls, risk_score: int) -> Dict[str, str]:
        """
        Classifies risk score into exactly one of three categories:
        1. NORMAL
        2. MAY BE SQL INJECTION
        3. SQL INJECTION
        """
        if risk_score <= config.NORMAL_THRESHOLD_MAX:
            return {
                "classification": "NORMAL",
                "decision": "ALLOW",
                "risk_level": "Low"
            }
        elif risk_score <= config.MAYBE_THRESHOLD_MAX:
            return {
                "classification": "MAY BE SQL INJECTION",
                "decision": "REVIEW",
                "risk_level": "Medium"
            }
        else:
            return {
                "classification": "SQL INJECTION",
                "decision": "BLOCK",
                "risk_level": "High"
            }
