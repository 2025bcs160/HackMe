"""
SQL Injection Scanner Module
"""

import requests
import re
import difflib
from urllib.parse import urljoin, urlparse, parse_qs
from typing import List, Dict, Tuple
from payloads import get_all_payloads, TIME_BASED_PAYLOADS, BOOLEAN_PAYLOADS, ERROR_PAYLOADS
import time

class SQLiScanner:
    DB_ERROR_PATTERNS = [
        r"SQL syntax", r"mysql_fetch", r"Warning.*mysql", r"MySQLException",
        r"ORA-\d{5}", r"PostgreSQL", r"SQL Server", r"MSSQL",
        r"Unclosed quotation", r"Syntax error", r"Unknown column",
        r"division by zero", r"SQLite3::", r"sqlite3\.OperationalError",
        r"ODBC Driver", r"JDBC", r"Database error", r"error in your SQL syntax",
        r"SQLSTATE", r"unterminated quoted string"
    ]

    RESPONSE_SIMILARITY_THRESHOLD = 0.92
    LENGTH_DIFF_RATIO = 0.12
    TIME_DELAY_THRESHOLD = 3.5

    def __init__(self, timeout=10, verify_ssl=True, default_headers=None, default_cookies=None, max_redirects=6, max_retries=2):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_retries = max_retries
        self.session = requests.Session()
        self.session.max_redirects = max_redirects

        if default_headers:
            self.session.headers.update(default_headers)

        if default_cookies:
            self.session.cookies.update(default_cookies)

    def _send_request(self, method: str, url: str, params=None, data=None, json_data=None, headers=None, allow_redirects=True) -> Dict:
        request_headers = self.session.headers.copy()
        if headers:
            request_headers.update(headers)

        attempt = 0
        last_exception = None
        while attempt <= self.max_retries:
            try:
                response = self.session.request(
                    method=method.upper(),
                    url=url,
                    params=params,
                    data=data,
                    json=json_data,
                    headers=request_headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=allow_redirects,
                )

                if response.status_code == 429 and attempt < self.max_retries:
                    sleep_time = 2 ** attempt
                    time.sleep(sleep_time)
                    attempt += 1
                    continue

                return {
                    "response": response,
                    "status_code": response.status_code,
                    "text": response.text,
                    "url": response.url,
                    "elapsed": response.elapsed.total_seconds(),
                    "history": len(response.history),
                    "headers": dict(response.headers),
                }
            except requests.exceptions.RequestException as exc:
                last_exception = exc
                if attempt >= self.max_retries:
                    raise
                time.sleep(1 + attempt)
                attempt += 1

        raise last_exception or requests.exceptions.RequestException("Request failed")

    def _normalize_text(self, text: str) -> str:
        return re.sub(r"\s+", " ", text or "").strip()

    def _text_similarity(self, a: str, b: str) -> float:
        if not a or not b:
            return 0.0
        return difflib.SequenceMatcher(None, self._normalize_text(a), self._normalize_text(b)).ratio()

    def _detect_db_error(self, response_text: str) -> Tuple[bool, str]:
        response_text = response_text or ""
        for pattern in self.DB_ERROR_PATTERNS:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                return True, match.group(0)
        return False, ""

    def _compare_responses(self, baseline: Dict, candidate: Dict) -> Dict:
        baseline_text = self._normalize_text(baseline.get("text", ""))
        candidate_text = self._normalize_text(candidate.get("text", ""))
        similarity = self._text_similarity(baseline_text, candidate_text)
        length_baseline = len(baseline_text)
        length_candidate = len(candidate_text)
        length_change = abs(length_candidate - length_baseline)
        length_pct = length_change / max(length_baseline, 1)

        db_error, error_fragment = self._detect_db_error(candidate_text)

        return {
            "status_changed": baseline.get("status_code") != candidate.get("status_code"),
            "redirect_changed": baseline.get("history", 0) != candidate.get("history", 0),
            "length_change": length_change,
            "length_pct": length_pct,
            "similarity": similarity,
            "time_delta": candidate.get("elapsed", 0.0) - baseline.get("elapsed", 0.0),
            "db_error": db_error,
            "error_fragment": error_fragment,
            "response_time": candidate.get("elapsed", 0.0),
        }

    def _score_sqli_evidence(self, comparison: Dict, payload: str) -> Tuple[str, List[str]]:
        evidence = []
        score = 0

        if comparison["db_error"]:
            evidence.append(f"Database error detected: {comparison['error_fragment']}")
            score += 4

        if comparison["time_delta"] > self.TIME_DELAY_THRESHOLD:
            evidence.append(f"Response delayed by {comparison['time_delta']:.2f}s")
            score += 4

        if comparison["status_changed"]:
            evidence.append("HTTP status code changed")
            score += 1

        if comparison["redirect_changed"]:
            evidence.append("Redirect behavior changed")
            score += 1

        if comparison["length_pct"] > self.LENGTH_DIFF_RATIO:
            evidence.append(f"Response length changed by {comparison['length_pct'] * 100:.1f}%")
            score += 1

        if comparison["similarity"] < self.RESPONSE_SIMILARITY_THRESHOLD:
            evidence.append(f"Page content changed significantly (similarity {comparison['similarity']:.2f})")
            score += 1

        if "UNION" in payload.upper() or "AND" in payload.upper() or "SELECT" in payload.upper():
            evidence.append("SQL-specific payload applied")
            score += 0

        if score >= 6:
            return "Confirmed", evidence
        elif score >= 4:
            return "High", evidence
        elif score >= 2:
            return "Medium", evidence
        elif evidence:
            return "Low", evidence
        return "None", []

    def _run_boolean_confirmation(self, method: str, url: str, param_name: str, baseline: Dict, params=None, data=None, json_data=None, headers=None) -> List[str]:
        try:
            true_payload = BOOLEAN_PAYLOADS[0]
            false_payload = BOOLEAN_PAYLOADS[1]

            if params is not None:
                true_params = params.copy(); true_params[param_name] = true_payload
                false_params = params.copy(); false_params[param_name] = false_payload
                true_resp = self._send_request(method, url, params=true_params, headers=headers)
                false_resp = self._send_request(method, url, params=false_params, headers=headers)
            elif data is not None:
                true_data = data.copy(); true_data[param_name] = true_payload
                false_data = data.copy(); false_data[param_name] = false_payload
                true_resp = self._send_request(method, url, data=true_data, headers=headers)
                false_resp = self._send_request(method, url, data=false_data, headers=headers)
            else:
                true_json = json_data.copy(); true_json[param_name] = true_payload
                false_json = json_data.copy(); false_json[param_name] = false_payload
                true_resp = self._send_request(method, url, json_data=true_json, headers=headers)
                false_resp = self._send_request(method, url, json_data=false_json, headers=headers)

            comparison = self._compare_responses(true_resp, false_resp)
            if comparison["similarity"] < self.RESPONSE_SIMILARITY_THRESHOLD or comparison["status_changed"] or comparison["length_pct"] > self.LENGTH_DIFF_RATIO:
                return ["Boolean-based test produced divergent responses"]
        except requests.exceptions.RequestException:
            pass

        return []

    def _run_time_based_confirmation(self, method: str, url: str, param_name: str, baseline: Dict, params=None, data=None, json_data=None, headers=None) -> List[str]:
        evidence = []
        for payload in TIME_BASED_PAYLOADS:
            try:
                if params is not None:
                    test_params = params.copy(); test_params[param_name] = payload
                    candidate = self._send_request(method, url, params=test_params, headers=headers)
                elif data is not None:
                    test_data = data.copy(); test_data[param_name] = payload
                    candidate = self._send_request(method, url, data=test_data, headers=headers)
                else:
                    test_json = json_data.copy(); test_json[param_name] = payload
                    candidate = self._send_request(method, url, json_data=test_json, headers=headers)

                comparison = self._compare_responses(baseline, candidate)
                if comparison["time_delta"] > self.TIME_DELAY_THRESHOLD:
                    evidence.append(f"Time-based confirmation payload delayed response by {comparison['time_delta']:.2f}s")
                    break
            except requests.exceptions.RequestException:
                continue
        return evidence

    def _run_error_confirmation(self, method: str, url: str, param_name: str, params=None, data=None, json_data=None, headers=None) -> List[str]:
        evidence = []
        for payload in ERROR_PAYLOADS:
            try:
                if params is not None:
                    test_params = params.copy(); test_params[param_name] = payload
                    candidate = self._send_request(method, url, params=test_params, headers=headers)
                elif data is not None:
                    test_data = data.copy(); test_data[param_name] = payload
                    candidate = self._send_request(method, url, data=test_data, headers=headers)
                else:
                    test_json = json_data.copy(); test_json[param_name] = payload
                    candidate = self._send_request(method, url, json_data=test_json, headers=headers)

                if self._detect_db_error(candidate.get("text", ""))[0]:
                    evidence.append("Error-based payload triggered database error message")
                    break
            except requests.exceptions.RequestException:
                continue
        return evidence

    def _prepare_result(self, param_type: str, param_name: str, payload: str, url: str, baseline: Dict, candidate: Dict, confidence: str, evidence: List[str]) -> Dict:
        comparison = self._compare_responses(baseline, candidate)
        result = {
            "type": param_type,
            "parameter": param_name,
            "payload": payload,
            "status_code": candidate.get("status_code"),
            "url": url,
            "confidence": confidence,
            "evidence": evidence,
            "baseline_status": baseline.get("status_code"),
            "baseline_length": len(self._normalize_text(baseline.get("text", ""))),
            "response_length": len(self._normalize_text(candidate.get("text", ""))),
            "response_time": candidate.get("elapsed", 0.0),
            "time_delta": comparison.get("time_delta", 0.0),
            "similarity": comparison.get("similarity", 0.0),
        }
        return result

    def _should_report(self, confidence: str, evidence: List[str]) -> bool:
        if confidence in ("Confirmed", "High", "Medium"):
            return True
        if confidence == "Low" and evidence:
            return True
        return False

    def test_url_parameters(self, url: str, method: str = "GET", payloads: List[str] = None, session_headers: Dict = None, session_cookies: Dict = None) -> List[Dict]:
        """
        Test URL parameters for SQL injection vulnerabilities
        """
        if payloads is None:
            payloads = get_all_payloads()

        if session_headers:
            self.session.headers.update(session_headers)
        if session_cookies:
            self.session.cookies.update(session_cookies)

        results = []
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        param_dict = {k: v[0] if v else "" for k, v in params.items()}

        if not param_dict:
            print("[*] No URL parameters found")
            return results

        print(f"\n[*] Testing {len(param_dict)} URL parameter(s)")
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        baseline = self._send_request("GET", base_url, params=param_dict)

        for param_name in param_dict.keys():
            boolean_evidence = self._run_boolean_confirmation("GET", base_url, param_name, baseline, params=param_dict)
            error_confirmation = []
            time_confirmation = []

            for payload in payloads:
                test_params = param_dict.copy()
                test_params[param_name] = payload

                try:
                    candidate = self._send_request("GET", base_url, params=test_params)
                    comparison = self._compare_responses(baseline, candidate)
                    confidence, evidence = self._score_sqli_evidence(comparison, payload)

                    if boolean_evidence:
                        evidence.extend(boolean_evidence)
                        if confidence == "Low":
                            confidence = "Medium"

                    if confidence in ("None", ""):
                        continue

                    if not error_confirmation and confidence in ("Medium", "High"):
                        error_confirmation = self._run_error_confirmation("GET", base_url, param_name, params=param_dict)
                        if error_confirmation:
                            evidence.extend(error_confirmation)
                            confidence = "Confirmed"

                    if not time_confirmation and confidence in ("Medium", "High"):
                        time_confirmation = self._run_time_based_confirmation("GET", base_url, param_name, baseline, params=param_dict)
                        if time_confirmation:
                            evidence.extend(time_confirmation)
                            confidence = "Confirmed"

                    if self._should_report(confidence, evidence):
                        results.append(self._prepare_result("GET Parameter", param_name, payload, candidate.get("url"), baseline, candidate, confidence, evidence))
                        print(f"[+] {confidence} SQLi: Parameter '{param_name}' with payload: {payload[:50]}")
                except requests.exceptions.RequestException as e:
                    print(f"[-] Error testing {param_name}: {str(e)}")

        return results

    def test_form_data(self, url: str, form_data: Dict, method: str = "POST", payloads: List[str] = None, session_headers: Dict = None, session_cookies: Dict = None) -> List[Dict]:
        """
        Test form data (POST/PUT) for SQL injection vulnerabilities
        """
        if payloads is None:
            payloads = get_all_payloads()

        if session_headers:
            self.session.headers.update(session_headers)
        if session_cookies:
            self.session.cookies.update(session_cookies)

        results = []
        print(f"\n[*] Testing {len(form_data)} form parameter(s)")
        baseline = self._send_request(method, url, data=form_data)

        for param_name in form_data.keys():
            boolean_evidence = self._run_boolean_confirmation(method, url, param_name, baseline, data=form_data)
            error_confirmation = []
            time_confirmation = []

            for payload in payloads:
                test_data = form_data.copy()
                test_data[param_name] = payload

                try:
                    candidate = self._send_request(method, url, data=test_data)
                    comparison = self._compare_responses(baseline, candidate)
                    confidence, evidence = self._score_sqli_evidence(comparison, payload)

                    if boolean_evidence:
                        evidence.extend(boolean_evidence)
                        if confidence == "Low":
                            confidence = "Medium"

                    if not error_confirmation and confidence in ("Medium", "High"):
                        error_confirmation = self._run_error_confirmation(method, url, param_name, data=form_data)
                        if error_confirmation:
                            evidence.extend(error_confirmation)
                            confidence = "Confirmed"

                    if not time_confirmation and confidence in ("Medium", "High"):
                        time_confirmation = self._run_time_based_confirmation(method, url, param_name, baseline, data=form_data)
                        if time_confirmation:
                            evidence.extend(time_confirmation)
                            confidence = "Confirmed"

                    if self._should_report(confidence, evidence):
                        results.append(self._prepare_result(f"{method} Parameter", param_name, payload, url, baseline, candidate, confidence, evidence))
                        print(f"[+] {confidence} SQLi: Parameter '{param_name}' with payload: {payload[:50]}")
                except requests.exceptions.RequestException as e:
                    print(f"[-] Error testing {param_name}: {str(e)}")

        return results

    def test_json_data(self, url: str, json_data: Dict, payloads: List[str] = None, session_headers: Dict = None, session_cookies: Dict = None) -> List[Dict]:
        """
        Test JSON data for SQL injection vulnerabilities
        """
        if payloads is None:
            payloads = get_all_payloads()

        if session_headers:
            self.session.headers.update(session_headers)
        if session_cookies:
            self.session.cookies.update(session_cookies)

        results = []
        print(f"\n[*] Testing {len(json_data)} JSON parameter(s)")
        baseline = self._send_request("POST", url, json_data=json_data)

        for param_name in json_data.keys():
            boolean_evidence = self._run_boolean_confirmation("POST", url, param_name, baseline, json_data=json_data)
            error_confirmation = []
            time_confirmation = []

            for payload in payloads:
                test_json = json_data.copy()
                test_json[param_name] = payload

                try:
                    candidate = self._send_request("POST", url, json_data=test_json)
                    comparison = self._compare_responses(baseline, candidate)
                    confidence, evidence = self._score_sqli_evidence(comparison, payload)

                    if boolean_evidence:
                        evidence.extend(boolean_evidence)
                        if confidence == "Low":
                            confidence = "Medium"

                    if not error_confirmation and confidence in ("Medium", "High"):
                        error_confirmation = self._run_error_confirmation("POST", url, param_name, json_data=json_data)
                        if error_confirmation:
                            evidence.extend(error_confirmation)
                            confidence = "Confirmed"

                    if not time_confirmation and confidence in ("Medium", "High"):
                        time_confirmation = self._run_time_based_confirmation("POST", url, param_name, baseline, json_data=json_data)
                        if time_confirmation:
                            evidence.extend(time_confirmation)
                            confidence = "Confirmed"

                    if self._should_report(confidence, evidence):
                        results.append(self._prepare_result("JSON Parameter", param_name, payload, url, baseline, candidate, confidence, evidence))
                        print(f"[+] {confidence} SQLi: JSON Parameter '{param_name}' with payload: {payload[:50]}")
                except requests.exceptions.RequestException as e:
                    print(f"[-] Error testing {param_name}: {str(e)}")

        return results

    def test_headers(self, url: str, headers: Dict, payloads: List[str] = None, session_headers: Dict = None, session_cookies: Dict = None) -> List[Dict]:
        """
        Test HTTP headers for SQL injection vulnerabilities
        """
        if payloads is None:
            payloads = BOOLEAN_PAYLOADS  # Use boolean-based payloads for headers

        if session_headers:
            self.session.headers.update(session_headers)
        if session_cookies:
            self.session.cookies.update(session_cookies)

        results = []
        print(f"\n[*] Testing {len(headers)} header(s)")
        baseline = self._send_request("GET", url, headers=headers)

        for header_name in headers.keys():
            boolean_evidence = self._run_boolean_confirmation("GET", url, header_name, baseline, headers=headers)
            error_confirmation = []
            time_confirmation = []

            for payload in payloads:
                test_headers = headers.copy()
                test_headers[header_name] = payload

                try:
                    candidate = self._send_request("GET", url, headers=test_headers)
                    comparison = self._compare_responses(baseline, candidate)
                    confidence, evidence = self._score_sqli_evidence(comparison, payload)

                    if boolean_evidence:
                        evidence.extend(boolean_evidence)
                        if confidence == "Low":
                            confidence = "Medium"

                    if not error_confirmation and confidence in ("Medium", "High"):
                        error_confirmation = self._run_error_confirmation("GET", url, header_name, headers=headers)
                        if error_confirmation:
                            evidence.extend(error_confirmation)
                            confidence = "Confirmed"

                    if not time_confirmation and confidence in ("Medium", "High"):
                        time_confirmation = self._run_time_based_confirmation("GET", url, header_name, baseline, headers=headers)
                        if time_confirmation:
                            evidence.extend(time_confirmation)
                            confidence = "Confirmed"

                    if self._should_report(confidence, evidence):
                        results.append(self._prepare_result("Header", header_name, payload, url, baseline, candidate, confidence, evidence))
                        print(f"[+] {confidence} SQLi: Header '{header_name}' with payload: {payload[:50]}")
                except requests.exceptions.RequestException as e:
                    print(f"[-] Error testing {header_name}: {str(e)}")

        return results

    def _check_sqli_indicators(self, response_text: str, payload: str) -> bool:
        """
        Check response for SQL injection indicators
        """
        db_error, _ = self._detect_db_error(response_text)
        if db_error:
            return True

        sql_keywords = ["UNION", "SELECT", "DATABASE", "information_schema", "INFORMATION_SCHEMA"]
        if any(keyword in response_text.upper() for keyword in sql_keywords):
            return True

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
            except requests.exceptions.RequestException:
                base_response_time = 0

        for payload in TIME_BASED_PAYLOADS:
            try:
                params = {param_name: payload}
                start = time.time()
                self.session.get(url, params=params, timeout=self.timeout + 10, verify=self.verify_ssl)
                response_time = time.time() - start

                if response_time > (base_response_time + self.TIME_DELAY_THRESHOLD):
                    print(f"[+] TIME-BASED SQLi DETECTED: Response delayed by {response_time:.2f}s")
                    return True
            except requests.exceptions.RequestException:
                pass

        return False
    
    def test_xss_url(self, url: str, payloads: List[str] = None) -> List[Dict]:
        """
        Test URL parameters for XSS vulnerabilities
        """
        from xss_payloads import get_all_xss_payloads
        if payloads is None:
            payloads = get_all_xss_payloads()
            
        results = []
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        # Convert to dict format expected by requests
        param_dict = {k: v[0] if v else "" for k, v in params.items()}
        
        if not param_dict:
            print("[*] No URL parameters found for XSS testing")
            return results
        
        print(f"\n[*] Testing {len(param_dict)} URL parameter(s) for XSS")
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
                    
                    # Check for XSS indicators in response
                    if self._check_xss_indicators(response.text, payload):
                        results.append({
                            "type": "XSS - URL Parameter",
                            "parameter": param_name,
                            "payload": payload,
                            "status_code": response.status_code,
                            "url": response.url,
                            "xss_type": self._classify_xss(payload)
                        })
                        print(f"[+] XSS VULNERABLE: Parameter '{param_name}' with payload: {payload[:50]}")
                        
                except requests.exceptions.RequestException as e:
                    print(f"[-] Error testing {param_name}: {str(e)}")
        
        return results
    
    def test_xss_form(self, url: str, form_data: Dict, method: str = "POST", payloads: List[str] = None) -> List[Dict]:
        """
        Test form data for XSS vulnerabilities (stored XSS)
        """
        from xss_payloads import get_xss_payloads_by_type
        if payloads is None:
            payloads = get_xss_payloads_by_type("stored")
            
        results = []
        print(f"\n[*] Testing {len(form_data)} form parameter(s) for XSS")
        
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
                    
                    # For stored XSS, we also check if the payload appears in subsequent requests
                    if self._check_xss_indicators(response.text, payload):
                        results.append({
                            "type": f"XSS - {method} Parameter",
                            "parameter": param_name,
                            "payload": payload,
                            "status_code": response.status_code,
                            "url": url,
                            "xss_type": self._classify_xss(payload)
                        })
                        print(f"[+] XSS VULNERABLE: Parameter '{param_name}' with payload: {payload[:50]}")
                        
                except requests.exceptions.RequestException as e:
                    print(f"[-] Error testing {param_name}: {str(e)}")
        
        return results
    
    def test_xss_dom(self, url: str, payloads: List[str] = None) -> List[Dict]:
        """
        Test for DOM-based XSS vulnerabilities
        """
        from xss_payloads import get_xss_payloads_by_type
        if payloads is None:
            payloads = get_xss_payloads_by_type("dom")
            
        results = []
        print(f"\n[*] Testing for DOM-based XSS")
        
        for payload in payloads:
            try:
                # For DOM-based XSS, we test with fragments/hashes
                test_url = url + payload
                response = self.session.get(
                    test_url,
                    timeout=self.timeout,
                    verify=self.verify_ssl
                )
                
                # Check if the payload is executed in the DOM
                if self._check_dom_xss_indicators(response.text, payload):
                    results.append({
                        "type": "XSS - DOM-based",
                        "parameter": "URL Fragment",
                        "payload": payload,
                        "status_code": response.status_code,
                        "url": test_url,
                        "xss_type": "DOM-based"
                    })
                    print(f"[+] DOM XSS VULNERABLE: {payload[:50]}")
                    
            except requests.exceptions.RequestException as e:
                print(f"[-] Error testing DOM XSS: {str(e)}")
        
        return results
    
    def _check_xss_indicators(self, response_text: str, payload: str) -> bool:
        """
        Check response for XSS indicators
        """
        from xss_payloads import XSS_INDICATORS
        
        # Check if payload appears unescaped in response
        if payload in response_text:
            # Additional checks for XSS patterns
            for pattern in XSS_INDICATORS:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True
        
        # Check for alert boxes or other XSS execution indicators
        if re.search(r"alert\s*\(", response_text, re.IGNORECASE):
            return True
            
        return False
    
    def _check_dom_xss_indicators(self, response_text: str, payload: str) -> bool:
        """
        Check for DOM-based XSS indicators
        """
        # For DOM XSS, check if the payload from URL fragment is processed
        fragment = payload.lstrip('#')
        if fragment in response_text:
            # Check for dangerous DOM methods
            dom_patterns = [
                r"document\.write\s*\(",
                r"eval\s*\(",
                r"innerHTML\s*=",
                r"outerHTML\s*=",
                r"location\.hash",
            ]
            for pattern in dom_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True
        
        return False
    
    def _classify_xss(self, payload: str) -> str:
        """
        Classify the type of XSS based on payload
        """
        if "<script>" in payload.lower() or "</script>" in payload.lower():
            return "Script Tag"
        elif "javascript:" in payload.lower():
            return "JavaScript URI"
        elif "on" in payload.lower() and "=" in payload:
            return "Event Handler"
        elif "<img" in payload.lower() or "<svg" in payload.lower():
            return "HTML Element"
        elif "#" in payload:
            return "DOM-based"
        else:
            return "Generic"
