from typing import Dict, Any
from backend.rule_detector import RuleDetector
from backend.risk_scoring import RiskScorer
from backend.prevention import PreventionEngine
from models.ml_detector import MLDetector

class SQLiDetectionEngine:
    """
    Master Detection Engine orchestrating:
    Input Normalization -> Rule Analysis -> ML Inference -> Risk Scoring -> Classification -> Prevention Decision
    """

    def __init__(self):
        self.rule_detector = RuleDetector()
        self.ml_detector = MLDetector()

    def analyze_query(self, raw_query: str) -> Dict[str, Any]:
        """
        Executes full detection pipeline on raw input string.
        """
        if not raw_query or not raw_query.strip():
            return {
                "error": "Empty input provided",
                "classification": "NORMAL",
                "risk_score": 0,
                "decision": "ALLOW",
                "detected_patterns": [],
                "detection_method": "LOCAL_RULE_ENGINE",
                "execution_status": "ALLOWED"
            }

        # 1. Rule-based detection & normalization
        rule_result = self.rule_detector.analyze(raw_query)

        # 2. Local Machine Learning inference
        ml_prob = self.ml_detector.predict_probability(rule_result["normalized_input"])
        detection_method = "LOCAL_HYBRID_ENGINE" if (ml_prob is not None) else "LOCAL_RULE_ENGINE"

        # 3. Risk scoring
        risk_score = RiskScorer.calculate_score(
            rule_score=rule_result["rule_score"],
            ml_probability=ml_prob
        )

        # 4. Three-way classification
        classification_info = RiskScorer.classify(risk_score)
        classification = classification_info["classification"]
        decision = classification_info["decision"]

        # 5. Prevention decision
        prevention_info = PreventionEngine.evaluate_prevention(classification, decision)

        return {
            "query_text": raw_query,
            "normalized_query": rule_result["normalized_input"],
            "classification": classification,
            "risk_score": risk_score,
            "decision": decision,
            "risk_level": classification_info["risk_level"],
            "detected_patterns": rule_result["detected_patterns"],
            "detection_method": detection_method,
            "ml_probability": ml_prob,
            "prevention_action": prevention_info["action"],
            "can_execute": prevention_info["can_execute"],
            "execution_status": prevention_info["action"],
            "message": prevention_info["message"]
        }
