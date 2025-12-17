#!/usr/bin/env python3
"""
Logging and Reporting Module
============================
Comprehensive logging for SQL injection scanning.
For educational and authorized testing purposes only.
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, asdict, field
from enum import Enum


class LogLevel(Enum):
    """Log severity levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    SUCCESS = "SUCCESS"
    VULN = "VULNERABILITY"


# ANSI color codes for terminal output
class Colors:
    """Terminal color codes."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    
    @classmethod
    def colorize(cls, text: str, color: str) -> str:
        """Apply color to text."""
        return f"{color}{text}{cls.RESET}"


LEVEL_COLORS = {
    LogLevel.DEBUG: Colors.WHITE,
    LogLevel.INFO: Colors.CYAN,
    LogLevel.WARNING: Colors.YELLOW,
    LogLevel.ERROR: Colors.RED,
    LogLevel.SUCCESS: Colors.GREEN,
    LogLevel.VULN: Colors.MAGENTA + Colors.BOLD,
}


@dataclass
class Finding:
    """Represents a vulnerability finding."""
    url: str
    parameter: str
    payload: str
    payload_type: str
    risk_level: str
    evidence: List[str]
    response_length: int
    response_time: float
    confidence: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class ScanSummary:
    """Summary of scan results."""
    target_url: str
    scan_start: str
    scan_end: str
    duration_seconds: float
    total_parameters: int
    total_payloads_tested: int
    total_requests: int
    vulnerabilities_found: int
    likely_vulnerable: int
    possibly_vulnerable: int
    findings: List[Finding]
    verdict: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data['findings'] = [f.to_dict() for f in self.findings]
        return data


class ScanLogger:
    """
    Comprehensive logger for SQL injection scanning.
    Supports console output with colors and JSON file export.
    """
    
    def __init__(
        self,
        output_file: Optional[str] = None,
        verbose: bool = False,
        no_color: bool = False,
    ):
        """
        Initialize the logger.
        
        Args:
            output_file: Path for JSON output file
            verbose: Enable verbose/debug output
            no_color: Disable colored output
        """
        self.output_file = Path(output_file) if output_file else None
        self.verbose = verbose
        self.no_color = no_color
        self.findings: List[Finding] = []
        self.scan_start: Optional[datetime] = None
        self.scan_end: Optional[datetime] = None
        self._request_count = 0
        self._params_tested = 0
        
        # Configure standard logging
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Configure Python logging."""
        self.logger = logging.getLogger("sqli_scanner")
        self.logger.setLevel(logging.DEBUG if self.verbose else logging.INFO)
        
        # Remove existing handlers
        self.logger.handlers.clear()
        
        # Console handler
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(handler)
    
    def _format_message(self, level: LogLevel, message: str) -> str:
        """Format message with optional color."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        level_str = f"[{level.value}]"
        
        if self.no_color:
            return f"{timestamp} {level_str:15} {message}"
        
        color = LEVEL_COLORS.get(level, Colors.WHITE)
        colored_level = Colors.colorize(level_str, color)
        return f"{Colors.colorize(timestamp, Colors.WHITE)} {colored_level:25} {message}"
    
    def log(self, level: LogLevel, message: str) -> None:
        """Log a message."""
        formatted = self._format_message(level, message)
        
        if level == LogLevel.DEBUG and not self.verbose:
            return
        
        if level == LogLevel.ERROR:
            self.logger.error(formatted)
        elif level == LogLevel.WARNING:
            self.logger.warning(formatted)
        else:
            self.logger.info(formatted)
    
    def debug(self, message: str) -> None:
        """Log debug message."""
        self.log(LogLevel.DEBUG, message)
    
    def info(self, message: str) -> None:
        """Log info message."""
        self.log(LogLevel.INFO, message)
    
    def warning(self, message: str) -> None:
        """Log warning message."""
        self.log(LogLevel.WARNING, message)
    
    def error(self, message: str) -> None:
        """Log error message."""
        self.log(LogLevel.ERROR, message)
    
    def success(self, message: str) -> None:
        """Log success message."""
        self.log(LogLevel.SUCCESS, message)
    
    def vulnerability(self, message: str) -> None:
        """Log vulnerability finding."""
        self.log(LogLevel.VULN, message)
    
    def start_scan(self, target_url: str) -> None:
        """Record scan start."""
        self.scan_start = datetime.now()
        self.info("=" * 60)
        self.info("SQL INJECTION VULNERABILITY SCANNER")
        self.info("=" * 60)
        self.info(f"Target: {target_url}")
        self.info(f"Started: {self.scan_start.isoformat()}")
        self.info("-" * 60)
    
    def end_scan(self) -> None:
        """Record scan end."""
        self.scan_end = datetime.now()
        self.info("-" * 60)
        self.info(f"Completed: {self.scan_end.isoformat()}")
    
    def log_request(self, url: str, parameter: str, payload: str) -> None:
        """Log an HTTP request."""
        self._request_count += 1
        self.debug(f"Testing: {parameter} = {payload[:30]}...")
    
    def log_finding(self, finding: Finding) -> None:
        """Log and store a vulnerability finding."""
        self.findings.append(finding)
        
        risk_color = {
            "low": Colors.YELLOW,
            "medium": Colors.MAGENTA,
            "high": Colors.RED + Colors.BOLD,
        }.get(finding.risk_level.lower(), Colors.WHITE)
        
        self.vulnerability(
            f"[{finding.risk_level.upper()}] Parameter: {finding.parameter} | "
            f"Payload: {finding.payload[:40]}... | "
            f"Confidence: {finding.confidence:.0%}"
        )
        
        for evidence in finding.evidence:
            self.info(f"  └─ {evidence}")
    
    def increment_params(self) -> None:
        """Increment tested parameters count."""
        self._params_tested += 1
    
    def generate_summary(self, target_url: str) -> ScanSummary:
        """Generate scan summary."""
        duration = (self.scan_end - self.scan_start).total_seconds() if self.scan_start and self.scan_end else 0
        
        likely = sum(1 for f in self.findings if f.confidence >= 0.6)
        possibly = sum(1 for f in self.findings if 0.3 <= f.confidence < 0.6)
        
        if likely > 0:
            verdict = "🔴 LIKELY VULNERABLE - Immediate attention required"
        elif possibly > 0:
            verdict = "🟡 POSSIBLY VULNERABLE - Further investigation recommended"
        else:
            verdict = "🟢 NO VULNERABILITIES DETECTED"
        
        return ScanSummary(
            target_url=target_url,
            scan_start=self.scan_start.isoformat() if self.scan_start else "",
            scan_end=self.scan_end.isoformat() if self.scan_end else "",
            duration_seconds=duration,
            total_parameters=self._params_tested,
            total_payloads_tested=self._request_count,
            total_requests=self._request_count,
            vulnerabilities_found=len(self.findings),
            likely_vulnerable=likely,
            possibly_vulnerable=possibly,
            findings=self.findings,
            verdict=verdict,
        )
    
    def print_summary(self, summary: ScanSummary) -> None:
        """Print scan summary to console."""
        self.info("")
        self.info("=" * 60)
        self.info("SCAN SUMMARY")
        self.info("=" * 60)
        self.info(f"Duration: {summary.duration_seconds:.2f} seconds")
        self.info(f"Parameters tested: {summary.total_parameters}")
        self.info(f"Total requests: {summary.total_requests}")
        self.info(f"Vulnerabilities found: {summary.vulnerabilities_found}")
        self.info(f"  - Likely vulnerable: {summary.likely_vulnerable}")
        self.info(f"  - Possibly vulnerable: {summary.possibly_vulnerable}")
        self.success("")
        self.success(summary.verdict)
        self.info("=" * 60)
    
    def export_json(self, summary: ScanSummary) -> Optional[str]:
        """Export results to JSON file."""
        if not self.output_file:
            return None
        
        try:
            self.output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.output_file, 'w') as f:
                json.dump(summary.to_dict(), f, indent=2)
            
            self.success(f"Results exported to: {self.output_file}")
            return str(self.output_file)
        except Exception as e:
            self.error(f"Failed to export results: {e}")
            return None


if __name__ == "__main__":
    # Demo: Logger functionality
    print("=" * 60)
    print("Logger Demo")
    print("=" * 60)
    
    logger = ScanLogger(verbose=True)
    logger.start_scan("http://example.com/test?id=1")
    
    logger.info("Discovered 2 parameters")
    logger.debug("Parameter 1: id (GET)")
    logger.debug("Parameter 2: name (GET)")
    
    logger.warning("Rate limiting activated")
    
    # Simulate finding
    finding = Finding(
        url="http://example.com/test?id=1",
        parameter="id",
        payload="' OR '1'='1",
        payload_type="boolean",
        risk_level="high",
        evidence=["SQL error detected: MySQL syntax error"],
        response_length=1500,
        response_time=0.35,
        confidence=0.75,
    )
    logger.log_finding(finding)
    
    logger.end_scan()
    
    summary = logger.generate_summary("http://example.com/test?id=1")
    logger.print_summary(summary)
