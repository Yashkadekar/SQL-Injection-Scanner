#!/usr/bin/env python3
"""
SQL Injection Vulnerability Scanner
====================================
Main scanner with CLI interface, parameter discovery, and concurrent testing.

⚠️ EDUCATIONAL USE ONLY
This tool is for authorized security testing only.
Only scan systems you own or have explicit permission to test.
Unauthorized access to computer systems is illegal.

Author: Security Research Team
"""

import argparse
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from dataclasses import dataclass

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("Error: Required packages not installed.")
    print("Run: pip install requests beautifulsoup4")
    sys.exit(1)

from payloads import Payload, PayloadType, get_all_payloads, get_quick_payloads, get_safe_payloads
from detector import SQLiDetector, VulnerabilityLevel, DetectionResult
from rate_limiter import TokenBucketRateLimiter
from logger import ScanLogger, Finding, ScanSummary


DISCLAIMER = """
╔═══════════════════════════════════════════════════════════════════════════╗
║                    ⚠️  LEGAL DISCLAIMER ⚠️                                  ║
╠═══════════════════════════════════════════════════════════════════════════╣
║                                                                           ║
║  This SQL Injection Scanner is provided for EDUCATIONAL PURPOSES ONLY.   ║
║                                                                           ║
║  By using this tool, you agree to:                                        ║
║  • Only scan systems you OWN or have WRITTEN PERMISSION to test           ║
║  • Accept full responsibility for your actions                            ║
║  • Not use this tool for any illegal activities                           ║
║  • Understand that unauthorized access is a criminal offense              ║
║                                                                           ║
║  Recommended test environments:                                           ║
║  • DVWA (Damn Vulnerable Web App)                                         ║
║  • OWASP Juice Shop                                                       ║
║  • bWAPP                                                                  ║
║  • Your own local test applications                                       ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
"""

@dataclass
class Parameter:
    """Represents an injectable parameter."""
    name: str
    value: str
    method: str  # GET or POST
    source: str  # url, form


class SQLiScanner:
    """
    Main SQL Injection Scanner class.
    Handles target discovery, payload injection, and result analysis.
    """
    
    def __init__(
        self,
        target_url: str,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        threads: int = 3,
        rate_limit: float = 3.0,
        timeout: float = 10.0,
        output_file: Optional[str] = None,
        verbose: bool = False,
        quick_scan: bool = False,
        skip_time_based: bool = False,
    ):
        """
        Initialize the scanner.
        
        Args:
            target_url: URL to scan
            cookies: Optional cookies for authenticated scanning
            headers: Optional custom headers
            threads: Number of concurrent threads
            rate_limit: Requests per second limit
            timeout: Request timeout in seconds
            output_file: Path for JSON report output
            verbose: Enable verbose logging
            quick_scan: Use reduced payload set
            skip_time_based: Skip time-based payloads
        """
        self.target_url = target_url
        self.timeout = timeout
        self.threads = threads
        self.quick_scan = quick_scan
        self.skip_time_based = skip_time_based
        
        # HTTP session setup
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
        })
        if cookies:
            self.session.cookies.update(cookies)
        if headers:
            self.session.headers.update(headers)
        
        # Components
        self.rate_limiter = TokenBucketRateLimiter(rate=rate_limit, capacity=5)
        self.logger = ScanLogger(output_file=output_file, verbose=verbose)
        self.detector: Optional[SQLiDetector] = None
        
        # Discovered parameters
        self.parameters: List[Parameter] = []
    
    def _parse_url_parameters(self) -> List[Parameter]:
        """Extract parameters from URL query string."""
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        return [
            Parameter(
                name=name,
                value=values[0] if values else "",
                method="GET",
                source="url"
            )
            for name, values in params.items()
        ]
    
    def _discover_form_parameters(self, html: str) -> List[Parameter]:
        """Extract parameters from HTML forms."""
        parameters = []
        
        try:
            soup = BeautifulSoup(html, 'html.parser')
            
            for form in soup.find_all('form'):
                method = form.get('method', 'GET').upper()
                
                # Input fields
                for inp in form.find_all(['input', 'textarea']):
                    name = inp.get('name')
                    if name:
                        value = inp.get('value', '')
                        parameters.append(Parameter(
                            name=name,
                            value=value,
                            method=method,
                            source="form"
                        ))
                
                # Select fields
                for select in form.find_all('select'):
                    name = select.get('name')
                    if name:
                        parameters.append(Parameter(
                            name=name,
                            value="",
                            method=method,
                            source="form"
                        ))
        except Exception as e:
            self.logger.debug(f"Form parsing error: {e}")
        
        return parameters
    
    def discover_parameters(self) -> List[Parameter]:
        """Discover all injectable parameters from target."""
        self.logger.info("Discovering injectable parameters...")
        
        # URL parameters
        url_params = self._parse_url_parameters()
        self.logger.debug(f"Found {len(url_params)} URL parameters")
        
        # Form parameters (fetch page first)
        form_params = []
        try:
            response = self.session.get(self.target_url, timeout=self.timeout)
            form_params = self._discover_form_parameters(response.text)
            self.logger.debug(f"Found {len(form_params)} form parameters")
            
            # Establish baseline for detector
            self.detector = SQLiDetector(
                baseline_response=response.text,
                baseline_length=len(response.text)
            )
        except requests.RequestException as e:
            self.logger.warning(f"Could not fetch page for form discovery: {e}")
            self.detector = SQLiDetector()
        
        # Combine and deduplicate
        seen: Set[str] = set()
        self.parameters = []
        
        for param in url_params + form_params:
            key = f"{param.name}:{param.method}"
            if key not in seen:
                seen.add(key)
                self.parameters.append(param)
        
        self.logger.info(f"Total parameters discovered: {len(self.parameters)}")
        for param in self.parameters:
            self.logger.debug(f"  • {param.name} ({param.method} - {param.source})")
        
        return self.parameters
    
    def _build_injected_url(self, param_name: str, payload: str) -> str:
        """Build URL with injected payload."""
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        # Replace parameter value with payload
        if param_name in params:
            params[param_name] = [payload]
        
        # Rebuild URL
        new_query = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
    
    def _test_payload(
        self, 
        param: Parameter, 
        payload: Payload
    ) -> Optional[Finding]:
        """
        Test a single parameter with a payload.
        
        Returns:
            Finding if vulnerability detected, None otherwise
        """
        # Rate limiting
        self.rate_limiter.acquire()
        
        try:
            start_time = time.time()
            
            if param.method == "GET":
                url = self._build_injected_url(param.name, payload.value)
                response = self.session.get(url, timeout=self.timeout)
            else:
                # POST request
                data = {param.name: payload.value}
                response = self.session.post(
                    self.target_url, 
                    data=data, 
                    timeout=self.timeout
                )
            
            elapsed = time.time() - start_time
            
            # Analyze response
            result = self.detector.analyze(
                response.text,
                elapsed,
                payload_type=payload.payload_type.value
            )
            
            self.logger.log_request(self.target_url, param.name, payload.value)
            
            # Check if vulnerable
            if result.level in (VulnerabilityLevel.LIKELY_VULNERABLE, 
                               VulnerabilityLevel.POSSIBLY_VULNERABLE):
                finding = Finding(
                    url=self.target_url,
                    parameter=param.name,
                    payload=payload.value,
                    payload_type=payload.payload_type.value,
                    risk_level=payload.risk_level,
                    evidence=result.evidence,
                    response_length=result.response_length,
                    response_time=result.response_time,
                    confidence=result.confidence_score,
                )
                return finding
            
            return None
            
        except requests.Timeout:
            # Timeout might indicate time-based SQLi
            if payload.payload_type == PayloadType.TIME:
                return Finding(
                    url=self.target_url,
                    parameter=param.name,
                    payload=payload.value,
                    payload_type="time",
                    risk_level="high",
                    evidence=["Request timeout - possible time-based injection"],
                    response_length=0,
                    response_time=self.timeout,
                    confidence=0.5,
                )
            return None
            
        except requests.RequestException as e:
            self.logger.debug(f"Request error: {e}")
            return None
    
    def scan(self) -> ScanSummary:
        """
        Execute the vulnerability scan.
        
        Returns:
            ScanSummary with results
        """
        self.logger.start_scan(self.target_url)
        
        # Discover parameters
        if not self.parameters:
            self.discover_parameters()
        
        if not self.parameters:
            self.logger.warning("No injectable parameters found!")
            self.logger.end_scan()
            return self.logger.generate_summary(self.target_url)
        
        # Select payloads
        if self.quick_scan:
            payloads = get_quick_payloads()
            self.logger.info(f"Quick scan mode: using {len(payloads)} payloads")
        elif self.skip_time_based:
            payloads = get_safe_payloads()
            self.logger.info(f"Safe mode: using {len(payloads)} payloads (no time-based)")
        else:
            payloads = get_all_payloads()
            self.logger.info(f"Full scan mode: using {len(payloads)} payloads")
        
        # Build test queue
        tests: List[Tuple[Parameter, Payload]] = [
            (param, payload)
            for param in self.parameters
            for payload in payloads
        ]
        
        self.logger.info(f"Total tests to run: {len(tests)}")
        self.logger.info("-" * 40)
        
        # Execute tests with thread pool
        findings: List[Finding] = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._test_payload, param, payload): (param, payload)
                for param, payload in tests
            }
            
            for future in as_completed(futures):
                param, payload = futures[future]
                
                try:
                    result = future.result()
                    if result:
                        findings.append(result)
                        self.logger.log_finding(result)
                except Exception as e:
                    self.logger.debug(f"Test error: {e}")
        
        # Mark parameters tested
        for _ in self.parameters:
            self.logger.increment_params()
        
        self.logger.end_scan()
        
        # Generate summary
        summary = self.logger.generate_summary(self.target_url)
        self.logger.print_summary(summary)
        
        # Export if output file specified
        self.logger.export_json(summary)
        
        return summary


def confirm_disclaimer() -> bool:
    """Display disclaimer and get user confirmation."""
    print(DISCLAIMER)
    
    try:
        response = input("\nDo you accept these terms and confirm authorization? (Y/N): ")
        return response.strip().upper() == 'Y'
    except (EOFError, KeyboardInterrupt):
        return False


def parse_cookies(cookie_str: str) -> Dict[str, str]:
    """Parse cookie string into dictionary."""
    cookies = {}
    for item in cookie_str.split(';'):
        if '=' in item:
            name, value = item.split('=', 1)
            cookies[name.strip()] = value.strip()
    return cookies


def main():
    """Main entry point with CLI."""
    parser = argparse.ArgumentParser(
        description="SQL Injection Vulnerability Scanner - Educational Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"
  %(prog)s -u "http://target.com/search?q=test" --quick
  %(prog)s -u "http://target.com/login" --cookie "PHPSESSID=abc123" -o report.json
        """
    )
    
    # Required arguments
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target URL to scan"
    )
    
    # Optional arguments
    parser.add_argument(
        "-c", "--cookie",
        help="Cookies for authenticated scanning (format: 'name1=value1; name2=value2')"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output file for JSON report"
    )
    
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=3,
        help="Number of concurrent threads (default: 3)"
    )
    
    parser.add_argument(
        "-r", "--rate",
        type=float,
        default=3.0,
        help="Requests per second limit (default: 3.0)"
    )
    
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Request timeout in seconds (default: 10.0)"
    )
    
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Quick scan with reduced payload set"
    )
    
    parser.add_argument(
        "--safe",
        action="store_true",
        help="Skip time-based payloads"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--accept-disclaimer",
        action="store_true",
        help="Accept legal disclaimer without prompt"
    )
    
    args = parser.parse_args()
    
    # Disclaimer check
    if not args.accept_disclaimer:
        if not confirm_disclaimer():
            print("\nDisclaimer not accepted. Exiting.")
            sys.exit(0)
    
    # Parse cookies
    cookies = parse_cookies(args.cookie) if args.cookie else None
    
    # Create and run scanner
    scanner = SQLiScanner(
        target_url=args.url,
        cookies=cookies,
        threads=args.threads,
        rate_limit=args.rate,
        timeout=args.timeout,
        output_file=args.output,
        verbose=args.verbose,
        quick_scan=args.quick,
        skip_time_based=args.safe,
    )
    
    try:
        summary = scanner.scan()
        
        # Exit code based on findings
        if summary.likely_vulnerable > 0:
            sys.exit(2)  # Critical vulnerabilities
        elif summary.possibly_vulnerable > 0:
            sys.exit(1)  # Possible vulnerabilities
        else:
            sys.exit(0)  # Clean
            
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
