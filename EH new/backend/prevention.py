from typing import Dict, Any

class PreventionEngine:
    """
    Prevention module that acts as a security firewall / gatekeeper.
    Rules:
    - NORMAL: ALLOW query execution
    - MAY BE SQL INJECTION: REVIEW / WARN (log warning, require user confirmation or inspection)
    - SQL INJECTION: BLOCK (prevent query execution completely, return security block response)
    """

    @staticmethod
    def evaluate_prevention(classification: str, decision: str) -> Dict[str, Any]:
        """
        Determines the execution status and prevention action message.
        """
        if classification == "SQL INJECTION" or decision == "BLOCK":
            return {
                "action": "BLOCKED",
                "can_execute": False,
                "status_code": 403,
                "message": "High-confidence SQL Injection attack blocked by security firewall."
            }
        elif classification == "MAY BE SQL INJECTION" or decision == "REVIEW":
            return {
                "action": "WARNING",
                "can_execute": True,
                "status_code": 200,
                "message": "Suspicious SQL injection patterns detected. Query flagged for security review."
            }
        else:
            return {
                "action": "ALLOWED",
                "can_execute": True,
                "status_code": 200,
                "message": "Query verified clean and allowed for execution."
            }
