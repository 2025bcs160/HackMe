"""
Configuration file for SQL Injection Scanner
Modify these settings to customize the scanner behavior
"""

# Request settings
DEFAULT_TIMEOUT = 10  # seconds
VERIFY_SSL = True     # Set to False to skip SSL verification

# Scanning settings
ENABLE_URL_SCANNING = True
ENABLE_FORM_SCANNING = True
ENABLE_JSON_SCANNING = True
ENABLE_HEADER_SCANNING = True
ENABLE_TIME_BASED_BLIND = True

# Payload settings
USE_ALL_PAYLOADS = True
PAYLOAD_CATEGORIES = [
    "basic",
    "boolean",
    "union",
    "comment"
]

# Response analysis settings
SQL_ERROR_DETECTION = True
MIN_RESPONSE_DELAY = 4  # seconds for time-based detection

# Test targets (optional)
TEST_TARGETS = [
    # Add your test targets here
    # "http://localhost/search.php?q=test",
    # "http://localhost/login.php",
]

# Report settings
REPORT_FORMAT = "text"  # Options: "text", "json", "csv"
GENERATE_REPORT_FILE = True
REPORT_DIRECTORY = "./reports"

# Logging
VERBOSE = True
LOG_FILE = "scanner.log"

# Advanced options
REQUEST_RETRY_COUNT = 1
REQUEST_RETRY_DELAY = 1  # seconds
MAX_CONCURRENT_REQUESTS = 5
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Database-specific options
MYSQL_SPECIFIC = False
POSTGRESQL_SPECIFIC = False
MSSQL_SPECIFIC = False
ORACLE_SPECIFIC = False
