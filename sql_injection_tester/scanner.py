"""
SQL Injection Scanner Module
"""

import requests
import re
from urllib.parse import urljoin, urlparse, parse_qs
from typing import List, Dict, Tuple
from payloads import get_all_payloads, TIME_BASED_PAYLOADS, BOOLEAN_PAYLOADS
import time

class SQLiScanner:
    def __init__(self, timeout=10, verify_ssl=True):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.vulnerable_params = []
        self.session = requests.Session()
        
    def test_url_parameters(self, url: str, method: str = "GET", payloads: List[str] = None) -> List[Dict]:
        """
        Test URL parameters for SQL injection vulnerabilities
        """
        if payloads is None:
            payloads = get_all_payloads()
            
        results = []
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        # Convert to dict format expected by requests
        param_dict = {k: v[0] if v else "" for k, v in params.items()}
        
        if not param_dict:
            print("[*] No URL parameters found")
            return results
        
        print(f"\n[*] Testing {len(param_dict)} URL parameter(s)")
        for param_name in param_dict.keys():
            for payload in payloads:
                test_params = param_dict.copy()
                test_params[param_name] = payload
                
                try:
                    response = self.session.get(
                        f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}",
                        params=test_params,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    # Check for SQLi indicators
                    if self._check_sqli_indicators(response.text, payload):
                        results.append({
                            "type": "GET Parameter",
                            "parameter": param_name,
                            "payload": payload,
                            "status_code": response.status_code,
                            "url": response.url
                        })
                        print(f"[+] VULNERABLE: Parameter '{param_name}' with payload: {payload[:50]}")
                        
                except requests.exceptions.RequestException as e:
                    print(f"[-] Error testing {param_name}: {str(e)}")
        
        return results
    
    def test_form_data(self, url: str, form_data: Dict, method: str = "POST", payloads: List[str] = None) -> List[Dict]:
        """
        Test form data (POST/PUT) for SQL injection vulnerabilities
        """
        if payloads is None:
            payloads = get_all_payloads()
            
        results = []
        print(f"\n[*] Testing {len(form_data)} form parameter(s)")
        
        for param_name in form_data.keys():
            for payload in payloads:
                test_data = form_data.copy()
                test_data[param_name] = payload
                
                try:
                    if method.upper() == "POST":
                        response = self.session.post(
                            url,
                            data=test_data,
                            timeout=self.timeout,
                            verify=self.verify_ssl
                        )
                    elif method.upper() == "PUT":
                        response = self.session.put(
                            url,
                            data=test_data,
                            timeout=self.timeout,
                            verify=self.verify_ssl
                        )
                    
                    if self._check_sqli_indicators(response.text, payload):
                        results.append({
                            "type": f"{method} Parameter",
                            "parameter": param_name,
                            "payload": payload,
                            "status_code": response.status_code,
                            "url": url
                        })
                        print(f"[+] VULNERABLE: Parameter '{param_name}' with payload: {payload[:50]}")
                        
                except requests.exceptions.RequestException as e:
                    print(f"[-] Error testing {param_name}: {str(e)}")
        
        return results
    
    def test_json_data(self, url: str, json_data: Dict, payloads: List[str] = None) -> List[Dict]:
        """
        Test JSON data for SQL injection vulnerabilities
        """
        if payloads is None:
            payloads = get_all_payloads()
            
        results = []
        print(f"\n[*] Testing {len(json_data)} JSON parameter(s)")
        
        for param_name in json_data.keys():
            for payload in payloads:
                test_json = json_data.copy()
                test_json[param_name] = payload
                
                try:
                    response = self.session.post(
                        url,
                        json=test_json,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    if self._check_sqli_indicators(response.text, payload):
                        results.append({
                            "type": "JSON Parameter",
                            "parameter": param_name,
                            "payload": payload,
                            "status_code": response.status_code,
                            "url": url
                        })
                        print(f"[+] VULNERABLE: JSON Parameter '{param_name}' with payload: {payload[:50]}")
                        
                except requests.exceptions.RequestException as e:
                    print(f"[-] Error testing {param_name}: {str(e)}")
        
        return results
    
    def test_headers(self, url: str, headers: Dict, payloads: List[str] = None) -> List[Dict]:
        """
        Test HTTP headers for SQL injection vulnerabilities
        """
        if payloads is None:
            payloads = BOOLEAN_PAYLOADS  # Use boolean-based payloads for headers
            
        results = []
        print(f"\n[*] Testing {len(headers)} header(s)")
        
        for header_name in headers.keys():
            for payload in payloads:
                test_headers = headers.copy()
                test_headers[header_name] = payload
                
                try:
                    response = self.session.get(
                        url,
                        headers=test_headers,
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    )
                    
                    if self._check_sqli_indicators(response.text, payload):
                        results.append({
                            "type": "Header",
                            "parameter": header_name,
                            "payload": payload,
                            "status_code": response.status_code,
                            "url": url
                        })
                        print(f"[+] VULNERABLE: Header '{header_name}' with payload: {payload[:50]}")
                        
                except requests.exceptions.RequestException as e:
                    print(f"[-] Error testing {header_name}: {str(e)}")
        
        return results
    
    def _check_sqli_indicators(self, response_text: str, payload: str) -> bool:
        """
        Check response for SQL injection indicators
        """
        # SQL error patterns
        error_patterns = [
            r"SQL syntax",
            r"mysql_fetch",
            r"Warning.*mysql",
            r"MySQLException",
            r"ORA-\d{5}",
            r"PostgreSQL",
            r"SQL Server",
            r"MSSQL",
            r"Unclosed quotation",
            r"Syntax error",
            r"UNION",
            r"SELECT",
            r"Database",
            r"table",
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        # Check for unusual response changes
        return False
    
    def test_time_based_blind(self, url: str, param_name: str, base_response_time: float = None) -> bool:
        """
        Test for time-based blind SQL injection
        """
        if base_response_time is None:
            try:
                start = time.time()
                self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
                base_response_time = time.time() - start
            except:
                base_response_time = 0
        
        for payload in TIME_BASED_PAYLOADS:
            try:
                params = {param_name: payload}
                start = time.time()
                self.session.get(url, params=params, timeout=self.timeout + 10, verify=self.verify_ssl)
                response_time = time.time() - start
                
                # If response is significantly delayed, likely vulnerable
                if response_time > (base_response_time + 4):
                    print(f"[+] TIME-BASED SQLi DETECTED: Response delayed by {response_time:.2f}s")
                    return True
            except:
                pass
        
        return False
