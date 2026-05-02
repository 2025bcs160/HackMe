# SQL Injection Vulnerability Scanner

A comprehensive Python-based command-line tool for testing SQL injection vulnerabilities in web applications and APIs. This tool is designed for **legitimate security testing on systems you own or have explicit permission to test**.

## Features

- **Multiple Input Vectors**: Test URL parameters, JSON APIs, form data (POST/PUT), and HTTP headers
- **Multiple SQLi Techniques**: 
  - Basic SQL injection
  - Boolean-based blind SQL injection
  - Time-based blind SQL injection
  - Union-based SQL injection
  - Error-based SQL injection
- **Report Generation**: Generate reports in text, JSON, and CSV formats
- **Easy-to-use CLI**: Simple command-line interface with comprehensive help
- **Color-coded Output**: Visual feedback for scan results

## Installation

1. **Clone or download the project**:
```bash
cd sql_injection_tester
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

## Quick Start

### Display Help
```bash
python main.py --help
python main.py scan-url --help
```

### Authorized .com and External Site Testing
This tool can scan any URL, including real `.com` domains, but only when you have explicit authorization.
For external targets, add `--confirm-authorization` to your scan command.

```bash
python main.py scan-url --url "https://example.com/search?q=test" --confirm-authorization
```

Only test websites you own or have written permission to audit. Unauthorized scanning is illegal.

### 1. Scan URL Parameters
Test a URL with query parameters:
```bash
python main.py scan-url --url "http://localhost/search.php?q=test&category=1"
```

With report output:
```bash
python main.py scan-url --url "http://localhost/search.php?q=test" --output report.txt
```

### 2. Test JSON API
Test a JSON API endpoint:
```bash
python main.py scan-json-api --url "http://api.localhost/search" --json-data '{"query":"test","limit":"10"}'
```

### 3. Test Form Data (POST)
Test form submissions:
```bash
python main.py scan-form --url "http://localhost/login" --data '{"username":"admin","password":"test"}' --method POST
```

### 4. Test HTTP Headers
Test custom headers for injection:
```bash
python main.py scan-headers --url "http://localhost/api" --headers '{"User-Agent":"test","X-API-Key":"key123"}'
```

### 5. View Available Payloads
See all SQL injection payloads used by the scanner:
```bash
python main.py payloads
```

## Command Reference

### scan-url
Scan URL query parameters for SQL injection.

**Options:**
- `--url` (required): Target URL with query parameters
- `--timeout` (default: 10): Request timeout in seconds
- `--skip-ssl`: Skip SSL certificate verification
- `--output`: Save text report to file
- `--json-output`: Save JSON report to file

**Example:**
```bash
python main.py scan-url --url "http://example.com/search.php?id=1" --output results.txt
```

### scan-json-api
Test JSON API parameters for SQL injection.

**Options:**
- `--url` (required): API endpoint URL
- `--json-data` (required): JSON payload as string
- `--timeout` (default: 10): Request timeout in seconds
- `--skip-ssl`: Skip SSL verification
- `--output`: Save report to file

**Example:**
```bash
python main.py scan-json-api --url "http://api.example.com/users" --json-data '{"id":"1","name":"test"}'
```

### scan-form
Test form data (POST/PUT) for SQL injection.

**Options:**
- `--url` (required): Target URL
- `--data` (required): Form data as JSON string
- `--method` (default: POST): HTTP method (POST or PUT)
- `--timeout` (default: 10): Request timeout in seconds
- `--skip-ssl`: Skip SSL verification
- `--output`: Save report to file

**Example:**
```bash
python main.py scan-form --url "http://example.com/register" --data '{"email":"test@test.com","username":"testuser"}'
```

### scan-headers
Test HTTP headers for SQL injection.

**Options:**
- `--url` (required): Target URL
- `--headers` (required): Headers as JSON string
- `--timeout` (default: 10): Request timeout in seconds
- `--skip-ssl`: Skip SSL verification
- `--output`: Save report to file

**Example:**
```bash
python main.py scan-headers --url "http://example.com" --headers '{"User-Agent":"Mozilla/5.0","X-Custom":"value"}'
```

### payloads
Display all available SQL injection payloads.

```bash
python main.py payloads
```

## XSS Scanning Commands

### scan-xss-url
Test URL parameters for Cross-Site Scripting (XSS) vulnerabilities.

**Options:**
- `--url` (required): Target URL with parameters
- `--timeout` (default: 10): Request timeout in seconds
- `--skip-ssl`: Skip SSL certificate verification
- `--output`: Save text report to file
- `--json-output`: Save JSON report to file

**Example:**
```bash
python main.py scan-xss-url --url "http://example.com/search.php?q=test" --output xss_results.txt
```

### scan-xss-form
Test form data (POST/PUT) for XSS vulnerabilities.

**Options:**
- `--url` (required): Target URL
- `--data` (required): Form data as JSON string
- `--method` (default: POST): HTTP method (POST or PUT)
- `--timeout` (default: 10): Request timeout in seconds
- `--skip-ssl`: Skip SSL verification
- `--output`: Save report to file

**Example:**
```bash
python main.py scan-xss-form --url "http://example.com/comment" --data '{"name":"test","comment":"test comment"}'
```

### scan-xss-dom
Test for DOM-based XSS vulnerabilities by analyzing JavaScript code.

**Options:**
- `--url` (required): Target URL
- `--timeout` (default: 10): Request timeout in seconds
- `--skip-ssl`: Skip SSL verification
- `--output`: Save report to file

**Example:**
```bash
python main.py scan-xss-dom --url "http://example.com/page" --output dom_xss_results.txt
```

### xss-payloads
Display all available XSS payloads organized by category.

```bash
python main.py xss-payloads
```

## Example Walkthrough

### Testing a Local Web Application

1. **Setup**: Assume you have a vulnerable PHP application at `http://localhost/search.php`

2. **Scan URL Parameters**:
```bash
python main.py scan-url --url "http://localhost/search.php?id=1&category=books"
```

Expected output:
```
[*] Starting SQL Injection scan on URL parameters...
[*] Testing 2 URL parameter(s)
[+] VULNERABLE: Parameter 'id' with payload: ' OR '1'='1
[+] VULNERABLE: Parameter 'id' with payload: ' OR 1=1--
...
```

3. **Generate Report**:
```bash
python main.py scan-url --url "http://localhost/search.php?id=1" --output vulnerability_report.txt
```

4. **Review Report**:
```bash
cat vulnerability_report.txt
```

## Common Payloads

The tool uses several categories of payloads:

### Basic Payloads
```
' OR '1'='1
' OR 1=1--
admin' --
```

### Union-Based
```
' UNION SELECT NULL--
' UNION SELECT NULL, NULL--
```

### Time-Based Blind
```
' AND SLEEP(5)--
' AND BENCHMARK(5000000, MD5('test'))--
```

### Boolean-Based
```
' AND '1'='1
' AND 1=2--
```

## Report Output

### Text Report
```
======================================================================
SQL INJECTION VULNERABILITY REPORT
======================================================================
Generated: 2024-04-28 10:30:45

[!] Found 3 potential vulnerabilities:

1. VULNERABILITY FOUND
----------------------------------------------------------------------
   Type:       GET Parameter
   Parameter:  id
   Payload:    ' OR '1'='1
   Status:     200
   URL:        http://localhost/search.php?id=' OR '1'='1
...
```

### JSON Report
```json
{
  "timestamp": "2024-04-28T10:30:45.123456",
  "total_vulnerabilities": 3,
  "vulnerabilities": [
    {
      "type": "GET Parameter",
      "parameter": "id",
      "payload": "' OR '1'='1",
      "status_code": 200,
      "url": "http://localhost/search.php?id=..."
    }
  ]
}
```

## Remediation Recommendations

The tool provides security recommendations:

1. **Use Parameterized Queries**: Use prepared statements with parameter binding
2. **Input Validation**: Validate and sanitize all user inputs
3. **Stored Procedures**: Use stored procedures with input parameters
4. **Least Privilege**: Database accounts should have minimal required permissions
5. **Web Application Firewall**: Deploy a WAF to detect and block SQLi attempts
6. **Security Testing**: Perform regular security audits and penetration testing

## Important Notes

⚠️ **LEGAL DISCLAIMER**: 
- Use this tool **ONLY** on systems you own or have **explicit written permission** to test
- Unauthorized testing is illegal in most jurisdictions
- The author is not responsible for misuse of this tool
- Always obtain proper authorization before conducting security tests

## Troubleshooting

### SSL Certificate Errors
Use the `--skip-ssl` flag:
```bash
python main.py scan-url --url "https://example.com/search" --skip-ssl
```

### Connection Timeouts
Increase the timeout value:
```bash
python main.py scan-url --url "http://example.com/search" --timeout 30
```

### JSON Format Errors
Ensure JSON strings are properly formatted:
```bash
# Correct
python main.py scan-json-api --json-data '{"id":"1"}'

# Incorrect (missing quotes around JSON)
python main.py scan-json-api --json-data {id:1}
```

## Project Structure

```
sql_injection_tester/
├── main.py              # Main CLI entry point
├── scanner.py           # SQLi scanning logic
├── payloads.py          # SQL injection payloads
├── reporter.py          # Report generation
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

## Future Enhancements

- [ ] Additional databases support (Oracle, MSSQL, PostgreSQL specific payloads)
- [ ] Recursive parameter discovery
- [ ] Proxy support for intercepting requests
- [ ] Multi-threading for faster scanning
- [ ] GUI dashboard
- [ ] Integration with vulnerability databases

## License

This tool is provided for educational and authorized security testing purposes only.

## References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
