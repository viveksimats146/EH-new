import re
import urllib.parse
from typing import List, Dict, Any, Tuple

class RuleDetector:
    """
    Rule-based SQL Injection Detector with multi-stage input normalization,
    pattern matching, and contextual feature extraction.
    """

    def __init__(self):
        # Patterns for high confidence SQL Injection attacks
        self.high_risk_patterns = [
            (
                r"(?i)\bOR\b\s+['\"]?\s*(\d+|[a-zA-Z]+)\s*['\"]?\s*=\s*['\"]?\1\s*['\"]?",
                "OR tautology (e.g., OR 1=1 or OR 'a'='a')",
                40
            ),
            (
                r"(?i)\bAND\b\s+['\"]?\s*(\d+|[a-zA-Z]+)\s*['\"]?\s*=\s*['\"]?\1\s*['\"]?",
                "AND tautology (e.g., AND 1=1 or AND 'a'='a')",
                35
            ),
            (
                r"(?i)\b(AND|OR)\b\s+['\"]?\s*(\d+)\s*['\"]?\s*(!=|<|>|<=|>=|<|>)\s*['\"]?\s*(\d+)\s*['\"]?",
                "Boolean-based comparison (e.g., AND 1=2 or OR 1>0)",
                30
            ),
            (
                r"(?i)\bUNION\b(\s+ALL|\s+DISTINCT)?\s+SELECT\b",
                "UNION-based SELECT injection",
                45
            ),
            (
                r"(?i);?\s*\b(DROP\s+TABLE|DROP\s+DATABASE|DELETE\s+FROM|TRUNCATE\s+TABLE|ALTER\s+TABLE|UPDATE\s+\w+\s+SET)\b",
                "Destructive SQL command execution (Stacked query)",
                50
            ),
            (
                r"(?i);?\s*\b(INSERT\s+INTO|EXEC|EXECUTE)\b",
                "Stacked statement or dynamic command execution",
                35
            ),
            (
                r"(?i)\b(SLEEP|BENCHMARK|PG_SLEEP)\s*\(\s*\d+\s*\)",
                "Time-based blind injection function (SLEEP/BENCHMARK)",
                45
            ),
            (
                r"(?i)\bWAITFOR\s+DELAY\b\s+['\"]\d+:\d+:\d+['\"]",
                "MSSQL WAITFOR DELAY time-based injection",
                45
            ),
            (
                r"(?i)\b(EXTRACTVALUE|UPDATEXML)\s*\(",
                "Error-based XML SQL injection function",
                40
            ),
            (
                r"(?i)\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\b",
                "Database file access / dump attack",
                45
            ),
            (
                r"(?i)\bINFORMATION_SCHEMA\b",
                "Information schema metadata enumeration",
                35
            ),
            (
                r"(?i)\b0x[0-9a-fA-F]{4,}\b",
                "Hexadecimal encoded payload",
                30
            ),
            (
                r"(?i)\bCHAR\s*\(\s*\d+(\s*,\s*\d+)*\s*\)",
                "CHAR() string construction obfuscation",
                30
            ),
            (
                r"(?i)/\*\![\s\S]*?\*/",
                "MySQL executable comment obfuscation (/*!...*/)",
                35
            ),
        ]

        # Medium risk patterns (suspicious indicators)
        self.medium_risk_patterns = [
            (
                r"(?i)(--|#)(\s|$)",
                "SQL comment indicator (-- or #)",
                20
            ),
            (
                r"(?i)/\*.+?\*/",
                "Inline multiline SQL comment",
                15
            ),
            (
                r"(?i)\b(HAVING|GROUP\s+BY|ORDER\s+BY)\s+\d+\b",
                "ORDER BY / GROUP BY numeric column enumeration",
                25
            ),
            (
                r"(?i)\bWHERE\s+[\w\.]+\s*=\s*[\w\.]+\s*(AND|OR)\b",
                "Suspicious SQL clause conjunction",
                15
            ),
            (
                r"(?i)['\"]\s*(OR|AND)\s+['\"]",
                "Quote wrapped logical operator",
                25
            ),
            (
                r"(?i)\b(CAST|CONVERT|CONCAT|CONCAT_WS|CHAR_LENGTH|ORD|HEX|UNHEX)\s*\(",
                "Suspicious SQL built-in function invocation",
                15
            ),
            (
                r"(?i)\b(VERSION|USER|DATABASE|SYSTEM_USER|CURRENT_USER)\s*\(\s*\)",
                "Database system metadata function",
                20
            ),
        ]

    def normalize_input(self, text: str) -> str:
        """
        Multi-pass URL decoding and whitespace / character normalization.
        """
        if not text:
            return ""

        decoded = text
        # Perform iterative URL decoding up to 3 times to unwrap nested encodings
        for _ in range(3):
            prev = decoded
            decoded = urllib.parse.unquote(decoded)
            if prev == decoded:
                break

        # Normalize unicode spaces and control characters
        decoded = re.sub(r'[\x00-\x1f\x7f-\x9f]', ' ', decoded)
        return decoded

    def detect_quote_anomalies(self, normalized_text: str) -> Tuple[int, List[str]]:
        """
        Analyzes quote balancing and break-out patterns like admin'-- or ' OR.
        """
        score = 0
        patterns = []

        single_quotes = normalized_text.count("'")
        double_quotes = normalized_text.count('"')

        # Check for odd single quotes (unbalanced quote breakout attempt)
        if single_quotes % 2 != 0:
            score += 15
            patterns.append("Unbalanced single quote indicator")

        # Check for admin'-- or root'#
        if re.search(r"(?i)\w+['\"]\s*(--|#)", normalized_text):
            score += 35
            patterns.append("Quote breakout followed immediately by comment (e.g. admin'--)")

        # Check for trailing quote with SQL operator: ' OR or ' AND
        if re.search(r"(?i)['\"]\s*(OR|AND)\b", normalized_text):
            score += 20
            patterns.append("Quote breakout followed by OR/AND keyword")

        return score, patterns

    def analyze(self, raw_input: str) -> Dict[str, Any]:
        """
        Analyzes the given raw query string and returns rule-based detection findings.
        """
        normalized = self.normalize_input(raw_input)
        detected_patterns = []
        total_rule_score = 0

        # 1. High risk pattern evaluation
        for pattern, desc, weight in self.high_risk_patterns:
            if re.search(pattern, normalized):
                total_rule_score += weight
                detected_patterns.append(desc)

        # 2. Medium risk pattern evaluation
        for pattern, desc, weight in self.medium_risk_patterns:
            if re.search(pattern, normalized):
                total_rule_score += weight
                detected_patterns.append(desc)

        # 3. Quote anomaly detection
        q_score, q_patterns = self.detect_quote_anomalies(normalized)
        if q_score > 0:
            total_rule_score += q_score
            detected_patterns.extend(q_patterns)

        # Deduplicate patterns while preserving order
        unique_patterns = list(dict.fromkeys(detected_patterns))

        return {
            "raw_input": raw_input,
            "normalized_input": normalized,
            "rule_score": total_rule_score,
            "detected_patterns": unique_patterns
        }
