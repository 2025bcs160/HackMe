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
    print("🚀 SQL Injection Learning - Quick Test Script")
    print("=" * 60)
    print("This script will test your SQL injection scanner")
    print("Make sure the vulnerable app is running on http://localhost:5000")
    print()

    # Check if vulnerable app is running
    print("Checking if vulnerable app is running...")
    try:
        import requests
        response = requests.get("http://localhost:5000", timeout=5)
        if response.status_code == 200:
            print("✅ Vulnerable app is running!")
        else:
            print("❌ Vulnerable app not responding")
            print("Please run: cd learning_setup && python vulnerable_app.py")
            return
    except:
        print("❌ Cannot connect to vulnerable app")
        print("Please run: cd learning_setup && python vulnerable_app.py")
        return

    # Change to the scanner directory
    scanner_dir = r"c:\Users\2025b.RAFFYG\Desktop\HackMe\sql_injection_tester"
    os.chdir(scanner_dir)

    print(f"\nChanged to scanner directory: {scanner_dir}")

    # Test 1: Basic URL parameter scanning
    run_command(
        'python main.py scan-url --url "http://localhost:5000/search?id=1"',
        "Test 1: Basic URL Parameter Scanning"
    )

    # Test 2: Login form scanning
    run_command(
        'python main.py scan-form --url "http://localhost:5000/login" --data "{\\"username\\":\\"admin\\",\\"password\\":\\"test\\"}"',
        "Test 2: Login Form Scanning"
    )

    # Test 3: API endpoint scanning
    run_command(
        'python main.py scan-json-api --url "http://localhost:5000/api/search" --json-data "{\\"query\\":\\"admin\\",\\"table\\":\\"users\\"}"',
        "Test 3: JSON API Scanning"
    )

    # Test 4: Generate report
    run_command(
        'python main.py scan-url --url "http://localhost:5000/search?id=1" --output learning_test_report.txt',
        "Test 4: Generate Report"
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