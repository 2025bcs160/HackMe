#!/usr/bin/env python3
"""
SQL Injection Vulnerability Scanner - CLI Tool
A comprehensive tool for testing SQL injection vulnerabilities in web applications and APIs
"""

import click
import json
import sys
from scanner import SQLiScanner
from reporter import Reporter
from colorama import Fore, Style, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)

@click.group()
def cli():
    """
    SQL Injection Testing Tool
    
    A comprehensive CLI tool for identifying SQL injection vulnerabilities in web applications and APIs.
    Only use this tool on systems you own or have explicit permission to test!
    """
    pass

@cli.command()
@click.option('--url', required=True, help='Target URL to scan')
@click.option('--timeout', default=10, help='Request timeout in seconds')
@click.option('--skip-ssl', is_flag=True, help='Skip SSL verification')
@click.option('--output', help='Output report file (text format)')
@click.option('--json-output', help='Output report file (JSON format)')
def scan_url(url, timeout, skip_ssl, output, json_output):
    """
    Scan URL parameters for SQL injection vulnerabilities
    
    Example: python main.py scan-url --url "http://example.com/search.php?q=test"
    """
    click.secho("[*] Starting SQL Injection scan on URL parameters...", fg='cyan')
    
    scanner = SQLiScanner(timeout=timeout, verify_ssl=not skip_ssl)
    results = scanner.test_url_parameters(url)
    
    # Generate reports
    if output or json_output:
        reporter_text = Reporter(output_format="text")
        if output:
            reporter_text.generate_report(results, output_file=output)
        
        reporter_json = Reporter(output_format="json")
        if json_output:
            reporter_json.generate_report(results, output_file=json_output)
    
    # Display summary
    click.echo("\n" + "=" * 70)
    if results:
        click.secho(f"[!] Found {len(results)} vulnerable parameter(s)!", fg='red', bold=True)
        for r in results:
            click.echo(f"    - {r['parameter']}: {r['payload'][:40]}...")
    else:
        click.secho("[+] No vulnerabilities found!", fg='green')
    click.echo("=" * 70)

@cli.command()
@click.option('--url', required=True, help='Target API endpoint URL')
@click.option('--json-data', required=True, help='JSON payload as string (e.g., \'{"id": "1"}\')')
@click.option('--timeout', default=10, help='Request timeout in seconds')
@click.option('--skip-ssl', is_flag=True, help='Skip SSL verification')
@click.option('--output', help='Output report file')
def scan_json_api(url, json_data, timeout, skip_ssl, output):
    """
    Test JSON API parameters for SQL injection
    
    Example: python main.py scan-json-api --url "http://api.example.com/search" --json-data '{"query":"test"}'
    """
    click.secho("[*] Starting SQL Injection scan on JSON API...", fg='cyan')
    
    try:
        data = json.loads(json_data)
    except json.JSONDecodeError:
        click.secho("[-] Invalid JSON format!", fg='red', bold=True)
        sys.exit(1)
    
    scanner = SQLiScanner(timeout=timeout, verify_ssl=not skip_ssl)
    results = scanner.test_json_data(url, data)
    
    if output:
        reporter = Reporter(output_format="text")
        reporter.generate_report(results, output_file=output)
    
    # Display summary
    click.echo("\n" + "=" * 70)
    if results:
        click.secho(f"[!] Found {len(results)} vulnerable parameter(s)!", fg='red', bold=True)
        for r in results:
            click.echo(f"    - {r['parameter']}: {r['payload'][:40]}...")
    else:
        click.secho("[+] No vulnerabilities found!", fg='green')
    click.echo("=" * 70)

@cli.command()
@click.option('--url', required=True, help='Target URL')
@click.option('--data', required=True, help='Form data as JSON string (e.g., \'{"username":"admin","password":"pass"}\')')
@click.option('--method', default='POST', type=click.Choice(['POST', 'PUT']), help='HTTP method')
@click.option('--timeout', default=10, help='Request timeout in seconds')
@click.option('--skip-ssl', is_flag=True, help='Skip SSL verification')
@click.option('--output', help='Output report file')
def scan_form(url, data, method, timeout, skip_ssl, output):
    """
    Test form data (POST/PUT) for SQL injection
    
    Example: python main.py scan-form --url "http://example.com/login" --data '{"username":"admin","password":"pass"}'
    """
    click.secho(f"[*] Starting SQL Injection scan on {method} form data...", fg='cyan')
    
    try:
        form_data = json.loads(data)
    except json.JSONDecodeError:
        click.secho("[-] Invalid JSON format!", fg='red', bold=True)
        sys.exit(1)
    
    scanner = SQLiScanner(timeout=timeout, verify_ssl=not skip_ssl)
    results = scanner.test_form_data(url, form_data, method=method)
    
    if output:
        reporter = Reporter(output_format="text")
        reporter.generate_report(results, output_file=output)
    
    # Display summary
    click.echo("\n" + "=" * 70)
    if results:
        click.secho(f"[!] Found {len(results)} vulnerable parameter(s)!", fg='red', bold=True)
        for r in results:
            click.echo(f"    - {r['parameter']}: {r['payload'][:40]}...")
    else:
        click.secho("[+] No vulnerabilities found!", fg='green')
    click.echo("=" * 70)

@cli.command()
@click.option('--url', required=True, help='Target URL')
@click.option('--headers', required=True, help='Headers as JSON string (e.g., \'{"User-Agent":"Test","X-Custom":"Value"}\')')
@click.option('--timeout', default=10, help='Request timeout in seconds')
@click.option('--skip-ssl', is_flag=True, help='Skip SSL verification')
@click.option('--output', help='Output report file')
def scan_headers(url, headers, timeout, skip_ssl, output):
    """
    Test HTTP headers for SQL injection vulnerabilities
    
    Example: python main.py scan-headers --url "http://example.com" --headers '{"User-Agent":"test","X-Custom":"test"}'
    """
    click.secho("[*] Starting SQL Injection scan on HTTP headers...", fg='cyan')
    
    try:
        headers_dict = json.loads(headers)
    except json.JSONDecodeError:
        click.secho("[-] Invalid JSON format!", fg='red', bold=True)
        sys.exit(1)
    
    scanner = SQLiScanner(timeout=timeout, verify_ssl=not skip_ssl)
    results = scanner.test_headers(url, headers_dict)
    
    if output:
        reporter = Reporter(output_format="text")
        reporter.generate_report(results, output_file=output)
    
    # Display summary
    click.echo("\n" + "=" * 70)
    if results:
        click.secho(f"[!] Found {len(results)} vulnerable parameter(s)!", fg='red', bold=True)
        for r in results:
            click.echo(f"    - {r['parameter']}: {r['payload'][:40]}...")
    else:
        click.secho("[+] No vulnerabilities found!", fg='green')
    click.echo("=" * 70)

@cli.command()
def payloads():
    """
    Display all available SQL injection payloads
    """
    from payloads import POST_PAYLOADS, get_all_payloads
    
    click.secho("\n[*] Available SQL Injection Payloads\n", fg='cyan', bold=True)
    
    for category, payload_list in POST_PAYLOADS.items():
        click.secho(f"{category.upper().replace('_', ' ')}:", fg='yellow', bold=True)
        for i, payload in enumerate(payload_list, 1):
            click.echo(f"  {i}. {payload}")
        click.echo()

if __name__ == '__main__':
    click.secho("""
    ╔════════════════════════════════════════════════════════════╗
    ║           SQL INJECTION VULNERABILITY SCANNER              ║
    ║                    Security Testing Tool                   ║
    ╚════════════════════════════════════════════════════════════╝
    """, fg='cyan', bold=True)
    
    click.secho("WARNING: Use only on systems you own or have permission to test!\n", fg='red', bold=True)
    
    cli()
