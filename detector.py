#!/usr/bin/env python3
"""
SQL Injection Vulnerability Detector
=====================================
Analyzes HTTP responses to detect SQL injection indicators.
For educational and authorized testing purposes only.
"""

import re
import time
from typing import Dict, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass


class VulnerabilityLevel(Enum):
    """Classification of vulnerability likelihood."""
    LIKELY_VULNERABLE = "LIKELY_VULNERABLE"
    POSSIBLY_VULNERABLE = "POSSIBLY_VULNERABLE"
    NOT_VULNERABLE = "NOT_VULNERABLE"


@dataclass
class DetectionResult:
    """Result of vulnerability detection analysis."""
    level: VulnerabilityLevel
    evidence: List[str]
    response_length: int
    response_time: float
    error_messages: List[str]
    confidence_score: float  # 0.0 to 1.0


# SQL Error patterns by database type
SQL_ERROR_PATTERNS: Dict[str, List[str]] = {
    "MySQL": [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySqlException",
        r"valid MySQL result",
        r"check the manual that corresponds to your MySQL server version",
        r"MySqlClient\.",
        r"com\.mysql\.jdbc\.exceptions",
        r"Unclosed quotation mark after the character string",
    ],
    "PostgreSQL": [
        r"PostgreSQL.*ERROR",
        r"Warning.*\Wpg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"PG::SyntaxError:",
        r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near",
    ],
    "Microsoft SQL Server": [
        r"Driver.*SQL[\-\_\ ]*Server",
        r"OLE DB.*SQL Server",
        r"\bSQL Server[^&lt;&quot;]+Driver",
        r"Warning.*mssql_",
        r"\bSQL Server[^&lt;&quot;]+[0-9a-fA-F]{8}",
        r"System\.Data\.SqlClient\.SqlException",
        r"(?s)Exception.*\WRoadhouse\.Cms\.",
        r"Microsoft SQL Native Client error '[0-9a-fA-F]{8}",
        r"ODBC SQL Server Driver",
        r"SQLServer JDBC Driver",
        r"macabordar",
        r"com\.jnetdirect\.jsql",
        r"Unclosed quotation mark after the character string",
    ],
    "Oracle": [
        r"\bORA-[0-9][0-9][0-9][0-9]",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*\Woci_",
        r"Warning.*\Wora_",
        r"oracle\.jdbc\.driver",
        r"quoted string not properly terminated",
    ],
    "SQLite": [
        r"SQLite/JDBCDriver",
        r"SQLite\.Exception",
        r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*sqlite_",
        r"Warning.*SQLite3::",
        r"\[SQLITE_ERROR\]",
        r"SQLite error \d+:",
        r"sqlite3\.OperationalError:",
        r"SQLite3::SQLException",
    ],
    "Generic": [
        r"SQL syntax",
        r"syntax error",
        r"mysql_fetch",
        r"num_rows",
        r"Unclosed quotation",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
        r"unexpected end of SQL command",
        r"Invalid SQL statement",
        r"Database error",
        r"SQLSTATE",
        r"HY000",
    ],
}

# Compiled regex patterns for efficiency
COMPILED_PATTERNS: Dict[str, List[re.Pattern]] = {
    db: [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    for db, patterns in SQL_ERROR_PATTERNS.items()
}


class SQLiDetector:
    """Detects SQL injection vulnerabilities in HTTP responses."""
    
    def __init__(
        self,
        baseline_response: Optional[str] = None,
        baseline_length: Optional[int] = None,
        time_threshold: float = 4.0,  # Seconds to consider time-based SQLi
        length_threshold: float = 0.25,  # 25% length difference threshold
    ):
        """
        Initialize the detector.
        
        Args:
            baseline_response: Original response content for comparison
            baseline_length: Original response length for comparison
            time_threshold: Minimum delay to consider time-based injection
            length_threshold: Percentage difference in length to flag
        """
        self.baseline_response = baseline_response
        self.baseline_length = baseline_length or (len(baseline_response) if baseline_response else 0)
        self.time_threshold = time_threshold
        self.length_threshold = length_threshold
    
    def detect_sql_errors(self, response_text: str) -> Tuple[List[str], List[str]]:
        """
        Scan response for SQL error messages.
        
        Returns:
            Tuple of (database_types, matched_errors)
        """
        databases_detected: List[str] = []
        errors_found: List[str] = []
        
        for db_type, patterns in COMPILED_PATTERNS.items():
            for pattern in patterns:
                matches = pattern.findall(response_text)
                if matches:
                    if db_type not in databases_detected:
                        databases_detected.append(db_type)
                    for match in matches[:3]:  # Limit to first 3 matches per pattern
                        error_str = match if isinstance(match, str) else str(match)
                        if error_str not in errors_found:
                            errors_found.append(error_str[:100])  # Truncate long matches
        
        return databases_detected, errors_found
    
    def detect_response_difference(self, response_text: str) -> Tuple[bool, float]:
        """
        Compare response with baseline to detect differences.
        
        Returns:
            Tuple of (is_different, difference_ratio)
        """
        if not self.baseline_length:
            return False, 0.0
        
        current_length = len(response_text)
        difference = abs(current_length - self.baseline_length)
        ratio = difference / self.baseline_length if self.baseline_length > 0 else 0.0
        
        return ratio > self.length_threshold, ratio
    
    def detect_time_based(self, response_time: float) -> bool:
        """Check if response time indicates time-based injection."""
        return response_time >= self.time_threshold
    
    def analyze(
        self,
        response_text: str,
        response_time: float,
        payload_type: str = "unknown"
    ) -> DetectionResult:
        """
        Perform comprehensive vulnerability analysis.
        
        Args:
            response_text: The HTTP response body
            response_time: Time taken for the request in seconds
            payload_type: Type of payload used (for context)
            
        Returns:
            DetectionResult with vulnerability assessment
        """
        evidence: List[str] = []
        confidence = 0.0
        
        # Check for SQL errors
        databases, errors = self.detect_sql_errors(response_text)
        if errors:
            evidence.append(f"SQL errors detected from: {', '.join(databases)}")
            confidence += 0.6  # Strong indicator
        
        # Check response length difference
        is_different, diff_ratio = self.detect_response_difference(response_text)
        if is_different:
            evidence.append(f"Response length differs by {diff_ratio:.1%} from baseline")
            confidence += 0.3
        
        # Check for time-based injection
        if payload_type == "time" and self.detect_time_based(response_time):
            evidence.append(f"Significant delay detected: {response_time:.2f}s")
            confidence += 0.7  # Strong indicator for time-based
        
        # Determine vulnerability level
        if confidence >= 0.6:
            level = VulnerabilityLevel.LIKELY_VULNERABLE
        elif confidence >= 0.3:
            level = VulnerabilityLevel.POSSIBLY_VULNERABLE
        else:
            level = VulnerabilityLevel.NOT_VULNERABLE
        
        return DetectionResult(
            level=level,
            evidence=evidence,
            response_length=len(response_text),
            response_time=response_time,
            error_messages=errors,
            confidence_score=min(confidence, 1.0)
        )
    
    def quick_check(self, response_text: str) -> bool:
        """
        Quick check if response contains any SQL error indicators.
        Useful for fast scanning.
        """
        _, errors = self.detect_sql_errors(response_text)
        return len(errors) > 0


def create_detector_with_baseline(
    baseline_url: str,
    session=None,
    timeout: float = 10.0
) -> SQLiDetector:
    """
    Create a detector by fetching baseline response.
    
    Args:
        baseline_url: URL to fetch baseline from
        session: Optional requests session
        timeout: Request timeout
        
    Returns:
        Configured SQLiDetector instance
    """
    import requests
    
    sess = session or requests.Session()
    start_time = time.time()
    
    try:
        response = sess.get(baseline_url, timeout=timeout)
        elapsed = time.time() - start_time
        
        return SQLiDetector(
            baseline_response=response.text,
            baseline_length=len(response.text),
        )
    except Exception as e:
        # Return detector without baseline
        print(f"Warning: Could not establish baseline: {e}")
        return SQLiDetector()


if __name__ == "__main__":
    # Demo: Test detector with sample responses
    print("=" * 60)
    print("SQLi Detector Demo")
    print("=" * 60)
    
    detector = SQLiDetector(baseline_length=1000)
    
    # Test with SQL error
    test_response = """
    <html>
    <body>
    Error: You have an error in your SQL syntax; check the manual 
    that corresponds to your MySQL server version for the right syntax 
    to use near ''' at line 1
    </body>
    </html>
    """
    
    result = detector.analyze(test_response, response_time=0.5)
    print(f"\nTest Response Analysis:")
    print(f"  Level: {result.level.value}")
    print(f"  Confidence: {result.confidence_score:.1%}")
    print(f"  Evidence: {result.evidence}")
    print(f"  Errors: {result.error_messages}")
