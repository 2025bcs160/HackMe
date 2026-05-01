#!/usr/bin/env python3
"""
Quick Test Script for SQL Injection Learning
This script demonstrates how to use your SQL injection scanner
on the vulnerable learning application.
"""

import subprocess
import time
import sys
import os

def run_command(cmd, description):
    """Run a command and show the output"""
    print(f"\n{'='*60}")
    print(f"🔍 {description}")
    print('='*60)

    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=os.getcwd())
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        return result.returncode == 0
    except Exception as e:
        print(f"Error running command: {e}")
        return False

def main():
    print("🚀 Cybersecurity Learning - Quick Test Script")
    print("=" * 60)
    print("This script will test your SQL injection and XSS scanners")
    print("Make sure both vulnerable apps are running:")
    print("- SQLi app: http://localhost:5000")
    print("- XSS app: http://localhost:5001")
    print()

    # Check if vulnerable apps are running
    sqli_running = False
    xss_running = False

    print("Checking if vulnerable apps are running...")
    try:
        import requests
        response = requests.get("http://localhost:5000", timeout=5)
        if response.status_code == 200:
            print("✅ SQL Injection app is running!")
            sqli_running = True
        else:
            print("❌ SQL Injection app not responding")
    except:
        print("❌ Cannot connect to SQL Injection app")

    try:
        response = requests.get("http://localhost:5001", timeout=5)
        if response.status_code == 200:
            print("✅ XSS app is running!")
            xss_running = True
        else:
            print("❌ XSS app not responding")
    except:
        print("❌ Cannot connect to XSS app")

    if not sqli_running and not xss_running:
        print("\nPlease run the vulnerable apps first:")
        print("cd learning_setup")
        print("python vulnerable_app.py      # SQLi on port 5000")
        print("python vulnerable_xss_app.py  # XSS on port 5001")
        return

    print("\nStarting scanner tests...")

    # Compute the scanner directory relative to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    scanner_dir = os.path.normpath(os.path.join(script_dir, "..", "sql_injection_tester"))

    if not os.path.isdir(scanner_dir):
        print(f"❌ Scanner directory not found: {scanner_dir}")
        return

    os.chdir(scanner_dir)
    print(f"\nChanged to scanner directory: {scanner_dir}")

    # SQL Injection Tests
    if sqli_running:
        print("\n🔍 SQL INJECTION TESTS")
        print("=" * 40)

        # Test 1: Basic URL parameter scanning
        run_command(
            'python main.py scan-url --url "http://localhost:5000/search?id=1"',
            "Test 1: SQLi - URL Parameter Scanning"
        )

        # Test 2: Login form scanning
        run_command(
            'python main.py scan-form --url "http://localhost:5000/login" --data "{\\"username\\":\\"admin\\",\\"password\\":\\"test\\"}"',
            "Test 2: SQLi - Login Form Scanning"
        )

        # Test 3: API endpoint scanning
        run_command(
            'python main.py scan-json-api --url "http://localhost:5000/api/search" --json-data "{\\"query\\":\\"admin\\",\\"table\\":\\"users\\"}"',
            "Test 3: SQLi - JSON API Scanning"
        )

    # XSS Tests
    if xss_running:
        print("\n🔍 XSS TESTS")
        print("=" * 40)

        # Test 4: XSS URL parameter scanning
        run_command(
            'python main.py scan-xss-url --url "http://localhost:5001/reflected?q=test"',
            "Test 4: XSS - Reflected XSS Scanning"
        )

        # Test 5: XSS form scanning
        run_command(
            'python main.py scan-xss-form --url "http://localhost:5001/stored" --data "{\\"name\\":\\"test\\",\\"comment\\":\\"test comment\\"}"',
            "Test 5: XSS - Stored XSS Form Scanning"
        )

        # Test 6: DOM-based XSS scanning
        run_command(
            'python main.py scan-xss-dom --url "http://localhost:5001/dom"',
            "Test 6: XSS - DOM-based XSS Scanning"
        )

    # Test 7: Generate report
    if sqli_running:
        run_command(
            'python main.py scan-url --url "http://localhost:5000/search?id=1" --output learning_test_report.txt',
            "Test 7: Generate Report"
    )

    print(f"\n{'='*60}")
    print("🎉 Testing Complete!")
    print('='*60)
    print("Check the generated report: learning_test_report.txt")
    print("\nNext steps:")
    print("1. Read CYBERSECURITY_LEARNING_GUIDE.md")
    print("2. Try manual testing in your browser")
    print("3. Experiment with different payloads")
    print("4. Learn how to prevent these vulnerabilities")
    print("\nRemember: This is for learning only!")
    print("Never test real websites without permission!")

if __name__ == "__main__":
    main()