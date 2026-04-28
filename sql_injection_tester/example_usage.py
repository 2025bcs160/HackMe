#!/usr/bin/env python3
"""
Example usage of SQL Injection Scanner as a library
This demonstrates programmatic usage without the CLI
"""

from scanner import SQLiScanner
from reporter import Reporter

def example_url_scanning():
    """Example: Scanning URL parameters"""
    print("[*] Example 1: Scanning URL parameters")
    print("-" * 50)
    
    scanner = SQLiScanner(timeout=10)
    url = "http://localhost/search.php?q=test&category=1"
    
    results = scanner.test_url_parameters(url)
    
    if results:
        print(f"[+] Found {len(results)} vulnerabilities!")
        for result in results:
            print(f"    - Parameter: {result['parameter']}")
            print(f"    - Payload: {result['payload']}")
    else:
        print("[-] No vulnerabilities found")
    print()

def example_form_scanning():
    """Example: Scanning form data"""
    print("[*] Example 2: Scanning form data (POST)")
    print("-" * 50)
    
    scanner = SQLiScanner(timeout=10)
    url = "http://localhost/login.php"
    form_data = {
        "username": "admin",
        "password": "password123"
    }
    
    results = scanner.test_form_data(url, form_data, method="POST")
    
    if results:
        print(f"[+] Found {len(results)} vulnerabilities!")
        for result in results:
            print(f"    - Parameter: {result['parameter']}")
            print(f"    - Payload: {result['payload']}")
    else:
        print("[-] No vulnerabilities found")
    print()

def example_json_api_scanning():
    """Example: Scanning JSON API"""
    print("[*] Example 3: Scanning JSON API")
    print("-" * 50)
    
    scanner = SQLiScanner(timeout=10)
    url = "http://localhost/api/users"
    json_data = {
        "id": "1",
        "search": "test"
    }
    
    results = scanner.test_json_data(url, json_data)
    
    if results:
        print(f"[+] Found {len(results)} vulnerabilities!")
        for result in results:
            print(f"    - Parameter: {result['parameter']}")
            print(f"    - Payload: {result['payload']}")
    else:
        print("[-] No vulnerabilities found")
    print()

def example_header_scanning():
    """Example: Scanning HTTP headers"""
    print("[*] Example 4: Scanning HTTP headers")
    print("-" * 50)
    
    scanner = SQLiScanner(timeout=10)
    url = "http://localhost/api"
    headers = {
        "User-Agent": "Mozilla/5.0",
        "X-API-Key": "test123"
    }
    
    results = scanner.test_headers(url, headers)
    
    if results:
        print(f"[+] Found {len(results)} vulnerabilities!")
        for result in results:
            print(f"    - Header: {result['parameter']}")
            print(f"    - Payload: {result['payload']}")
    else:
        print("[-] No vulnerabilities found")
    print()

def example_report_generation():
    """Example: Generating reports"""
    print("[*] Example 5: Generating Reports")
    print("-" * 50)
    
    # Mock vulnerability results
    results = [
        {
            "type": "GET Parameter",
            "parameter": "id",
            "payload": "' OR '1'='1",
            "status_code": 200,
            "url": "http://localhost/search.php?id=..."
        },
        {
            "type": "POST Parameter",
            "parameter": "username",
            "payload": "admin' --",
            "status_code": 200,
            "url": "http://localhost/login.php"
        }
    ]
    
    # Generate text report
    reporter_text = Reporter(output_format="text")
    text_report = reporter_text.generate_report(results, output_file="report.txt")
    print("[+] Text report generated and saved to report.txt")
    
    # Generate JSON report
    reporter_json = Reporter(output_format="json")
    json_report = reporter_json.generate_report(results, output_file="report.json")
    print("[+] JSON report generated and saved to report.json")
    
    # Generate CSV report
    reporter_csv = Reporter(output_format="csv")
    csv_report = reporter_csv.generate_report(results, output_file="report.csv")
    print("[+] CSV report generated and saved to report.csv")
    print()

def example_custom_payloads():
    """Example: Using custom payloads"""
    print("[*] Example 6: Using custom payloads")
    print("-" * 50)
    
    custom_payloads = [
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "admin' --"
    ]
    
    scanner = SQLiScanner(timeout=10)
    url = "http://localhost/search.php?q=test"
    
    results = scanner.test_url_parameters(url, payloads=custom_payloads)
    
    if results:
        print(f"[+] Found {len(results)} vulnerabilities with custom payloads!")
    else:
        print("[-] No vulnerabilities found with custom payloads")
    print()

if __name__ == "__main__":
    print("=" * 50)
    print("SQL Injection Scanner - Library Usage Examples")
    print("=" * 50)
    print()
    
    # Note: These examples assume a local vulnerable web app is running
    # For actual usage, replace URLs with your test targets
    
    print("[!] WARNING: Run these examples only on systems you own!")
    print("[!] Make sure you have a test web server running locally")
    print()
    
    try:
        # Uncomment examples to run them
        # example_url_scanning()
        # example_form_scanning()
        # example_json_api_scanning()
        # example_header_scanning()
        example_report_generation()
        # example_custom_payloads()
        
        print("[+] Examples completed!")
        
    except Exception as e:
        print(f"[-] Error running examples: {str(e)}")
        print("[*] Make sure your test web server is running and accessible")
