# SQL Injection Vulnerability Scanner

<div align="center">

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Security](https://img.shields.io/badge/purpose-educational-orange.svg)

**An educational SQL injection vulnerability scanner for authorized security testing.**

</div>

---

## ⚠️ Legal Disclaimer

> **This tool is provided for EDUCATIONAL and AUTHORIZED SECURITY TESTING purposes only.**
>
> - Only scan systems you **own** or have **explicit written permission** to test
> - Unauthorized access to computer systems is **illegal**
> - The authors are not responsible for misuse of this tool

**Recommended test environments:**
- [DVWA](https://github.com/digininja/DVWA) (Damn Vulnerable Web App)
- [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
- [bWAPP](http://www.itsecgames.com/)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🎯 **Multi-DB Detection** | MySQL, PostgreSQL, MSSQL, Oracle, SQLite |
| 🔍 **50+ Payloads** | Boolean, error, time, comment, union-based |
| ⚡ **Concurrent Scanning** | Multi-threaded with configurable threads |
| 🛡️ **Rate Limiting** | Token bucket algorithm prevents server overload |
| 📊 **JSON Reports** | Export detailed findings for analysis |
| 🎨 **Colored Output** | Real-time console feedback |
| 🔐 **Session Support** | Cookie/header support for authenticated testing |

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/Yashkadekar/SQL-Injection-Scanner.git
cd SQL-Injection-Scanner

# Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Usage

### Basic Scan

```bash
python scanner.py -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"
```

### Quick Scan (Fewer Payloads)

```bash
python scanner.py -u "http://target.com/search?q=test" --quick
```

### Authenticated Scan with Report

```bash
python scanner.py -u "http://target.com/profile" \
    --cookie "PHPSESSID=abc123; security=low" \
    -o report.json
```

### Full Options

```bash
python scanner.py --help

Options:
  -u, --url URL           Target URL to scan (required)
  -c, --cookie COOKIES    Cookies for authenticated scanning
  -o, --output FILE       Output file for JSON report
  -t, --threads N         Number of concurrent threads (default: 3)
  -r, --rate N            Requests per second limit (default: 3.0)
  --timeout SECONDS       Request timeout (default: 10.0)
  --quick                 Quick scan with reduced payloads
  --safe                  Skip time-based payloads
  -v, --verbose           Enable verbose output
  --accept-disclaimer     Skip legal disclaimer prompt
```

---

## 📁 Project Structure

```
SQL-Injection-Scanner/
├── scanner.py          # Main scanner with CLI interface
├── payloads.py         # SQL injection payload definitions
├── detector.py         # Vulnerability detection logic
├── rate_limiter.py     # Request throttling (token bucket)
├── logger.py           # Logging and reporting
├── requirements.txt    # Python dependencies
└── README.md           # Documentation
```

### Module Overview

| Module | Purpose |
|--------|---------|
| `payloads.py` | 50+ SQL injection payloads organized by type (boolean, error, time, comment, union) |
| `detector.py` | Response analysis for SQL errors, length differences, and time delays |
| `rate_limiter.py` | Token bucket rate limiting to prevent server overload |
| `logger.py` | Colored console output and JSON report generation |
| `scanner.py` | CLI interface, parameter discovery, and concurrent test execution |

---

## 🧪 Testing with DVWA

1. **Start DVWA** (Docker recommended):
   ```bash
   docker run -d -p 80:80 vulnerables/web-dvwa
   ```

2. **Login** to DVWA at `http://localhost` (admin/password)

3. **Set security to Low** in DVWA Security settings

4. **Run the scanner**:
   ```bash
   python scanner.py -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
       --cookie "PHPSESSID=<your-session>; security=low" \
       --accept-disclaimer
   ```

---

## 📊 Sample Output

```
════════════════════════════════════════════════════════════
SQL INJECTION VULNERABILITY SCANNER
════════════════════════════════════════════════════════════
Target: http://localhost/dvwa/vulnerabilities/sqli/?id=1
Started: 2024-12-17T21:40:00

Discovering injectable parameters...
Total parameters discovered: 2
Full scan mode: using 45 payloads
Total tests to run: 90
────────────────────────────────────────

[VULNERABILITY] [HIGH] Parameter: id | Payload: ' OR '1'='1... | Confidence: 75%
  └─ SQL errors detected from: MySQL

════════════════════════════════════════════════════════════
SCAN SUMMARY
════════════════════════════════════════════════════════════
Duration: 12.34 seconds
Parameters tested: 2
Total requests: 90
Vulnerabilities found: 3
  - Likely vulnerable: 2
  - Possibly vulnerable: 1

🔴 LIKELY VULNERABLE - Immediate attention required
════════════════════════════════════════════════════════════
```

---

## 🔧 Detection Techniques

### 1. Error-Based Detection
Identifies SQL errors in responses:
- MySQL: `"You have an error in your SQL syntax"`
- PostgreSQL: `"ERROR: syntax error at or near"`
- MSSQL: `"Unclosed quotation mark"`

### 2. Boolean-Based Detection
Compares response length/content between:
- Normal request
- Injected true condition (`' OR '1'='1`)
- Injected false condition (`' AND '1'='2`)

### 3. Time-Based Detection
Measures response time for payloads like:
- MySQL: `' OR SLEEP(5)--`
- PostgreSQL: `' OR pg_sleep(5)--`
- MSSQL: `'; WAITFOR DELAY '0:0:5'--`

---

## 🛠️ Extending the Scanner

### Adding Custom Payloads

Edit `payloads.py`:

```python
CUSTOM_PAYLOADS = [
    Payload("' OR 1=1#", PayloadType.BOOLEAN, "Custom MySQL bypass", "high"),
]
```

### Adding Error Patterns

Edit `detector.py`:

```python
SQL_ERROR_PATTERNS["CustomDB"] = [
    r"CustomDB error message pattern",
]
```

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- [OWASP](https://owasp.org/) for security testing guidelines
- [DVWA](https://github.com/digininja/DVWA) for providing a safe testing environment

---

<div align="center">

**Built for learning. Use responsibly. Stay ethical.** 🔐

</div>