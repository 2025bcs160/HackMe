# Cybersecurity Learning Guide - SQL Injection & XSS

## 🎓 Welcome to Cybersecurity Learning!

This guide will help you learn about SQL injection and Cross-Site Scripting (XSS) vulnerabilities safely and ethically. We'll use intentionally vulnerable applications that you can test with your security scanner.

## ⚠️ IMPORTANT: Ethical Hacking Rules

### ✅ What You CAN Do:
- Test applications you own or created
- Use intentionally vulnerable learning platforms
- Practice on your own local machines
- Learn from authorized cybersecurity courses

### ❌ What You CANNOT Do:
- Test websites you don't own without permission
- Scan public websites without authorization
- Use vulnerabilities to harm others
- Break into systems without permission

**Remember**: Unauthorized hacking is illegal and can result in serious consequences!

---

## 🛠️ Setting Up Your Learning Environment

### Step 1: Install Dependencies

Run the setup script:
```batch
cd c:\Users\2025b.RAFFYG\Desktop\HackMe\learning_setup
setup_and_run.bat
```

This will:
- Install Flask (web framework)
- Start vulnerable applications:
  - SQL Injection app on `http://localhost:5000`
  - XSS app on `http://localhost:5001`

### Step 2: Start the Vulnerable Apps

The setup script will automatically start both vulnerable applications. You'll see:
```
🚨 LEARNING SQL INJECTION LAB 🚨
Starting server on http://localhost:5000

🚨 LEARNING XSS LAB 🚨
Starting server on http://localhost:5001
```

### Step 3: Test with Your Scanner

Now use your security scanner on the local apps:

**SQL Injection Testing:**
```batch
# Test URL parameters
python main.py scan-url --url "http://localhost:5000/search?id=1"

# Test login form
python main.py scan-form --url "http://localhost:5000/login" --data '{"username":"admin","password":"test"}'

# Test API endpoints
python main.py scan-json-api --url "http://localhost:5000/api/search" --json-data '{"query":"admin","table":"users"}'
```

**XSS Testing:**
```batch
# Test reflected XSS
python main.py scan-xss-url --url "http://localhost:5001/reflected?q=test"

# Test stored XSS
python main.py scan-xss-form --url "http://localhost:5001/stored" --data '{"name":"test","comment":"test comment"}'

# Test DOM-based XSS
python main.py scan-xss-dom --url "http://localhost:5001/dom"
```

---

## 🎯 Learning Objectives

### 1. Understand SQL Injection Basics

SQL injection occurs when user input is directly concatenated into SQL queries without proper sanitization.

**Vulnerable Code Example:**
```python
# DANGEROUS - Never do this!
user_id = request.args.get('id')
query = f"SELECT * FROM users WHERE id = {user_id}"  # Direct concatenation
```

**Safe Code Example:**
```python
# SAFE - Use parameterized queries
user_id = request.args.get('id')
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

### 2. Learn XSS (Cross-Site Scripting)

XSS occurs when user input is displayed in web pages without proper sanitization, allowing attackers to inject malicious scripts.

#### Types of XSS:

**A. Reflected XSS** - Input is immediately returned in the response
- Test: `http://localhost:5001/reflected?q=<script>alert('XSS')</script>`

**B. Stored XSS** - Input is stored and displayed later
- Test: Post a comment with `<script>alert('XSS')</script>`

**C. DOM-based XSS** - Input is processed by client-side JavaScript
- Test: `http://localhost:5001/dom#<script>alert('XSS')</script>`

**Safe Code Example:**
```python
# SAFE - Sanitize output
from html import escape
user_input = request.args.get('q', '')
safe_output = escape(user_input)  # Escapes < > & "
```

### 3. Types of SQL Injection

#### A. Classic SQLi (URL Parameters)
Test: `http://localhost:5000/search?id=1' OR '1'='1`

#### B. Login Bypass
Test the login form with: `username: admin' --` and any password

#### C. Union-Based SQLi
Test: `http://localhost:5000/search?id=-1 UNION SELECT 1,username,password FROM users`

#### D. Error-Based SQLi
Test: `http://localhost:5000/search?id=1 AND extractvalue(1,concat(0x7e,(SELECT database())))`

#### E. Blind SQLi
Test: `http://localhost:5000/search?id=1 AND SLEEP(5)`

---

## 🧪 Hands-On Exercises

### Exercise 1: Basic SQL Injection
1. Visit: `http://localhost:5000/search?id=1`
2. Try: `http://localhost:5000/search?id=1' OR '1'='1`
3. What happens? Why?

### Exercise 2: Login Bypass
1. Go to: `http://localhost:5000/login`
2. Username: `admin' --`
3. Password: `anything`
4. Why does this work?

### Exercise 3: Extract Database Info
1. Try: `http://localhost:5000/search?id=-1 UNION SELECT 1,sqlite_version(),3`
2. What information do you get?

### Exercise 4: API Testing
1. Test: `http://localhost:5000/api/users/1' OR '1'='1`
2. Try: `http://localhost:5000/api/search` with JSON payload

### Exercise 5: Reflected XSS
1. Visit: `http://localhost:5001/reflected?q=test`
2. Try: `http://localhost:5001/reflected?q=<script>alert('XSS')</script>`
3. What happens?

### Exercise 6: Stored XSS
1. Go to: `http://localhost:5001/stored`
2. Post a comment with: `<script>alert('XSS')</script>`
3. View the comments - does the alert execute?

### Exercise 7: DOM-based XSS
1. Visit: `http://localhost:5001/dom`
2. Change URL to: `http://localhost:5001/dom#<script>alert('XSS')</script>`
3. Does the script execute?

---

## 🔍 Analyzing Your Results

### What to Look For:

**SQL Injection:**
1. **Unexpected Data**: If you see other users' information
2. **Database Errors**: Messages like "SQL syntax error"
3. **Bypassed Authentication**: Logging in without correct password
4. **Information Disclosure**: Database version, table names, etc.

**XSS:**
1. **Alert Boxes**: JavaScript `alert()` popups
2. **HTML Injection**: Unexpected HTML elements
3. **Script Execution**: Any JavaScript running from your input
4. **Cookie Theft**: Scripts trying to access `document.cookie`

### Common Payloads to Try:

**SQL Injection:**
```
' OR '1'='1
' OR 1=1 --
admin' --
' UNION SELECT NULL --
' AND SLEEP(5) --
```

**XSS:**
```
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
javascript:alert('XSS')
<body onload=alert('XSS')>
```
' OR '1'='1
' OR 1=1 --
admin' --
' UNION SELECT NULL --
' AND SLEEP(5) --
```

---

## 🛡️ Prevention Techniques

### SQL Injection Prevention:

### 1. Use Parameterized Queries
```python
# Instead of:
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# Use:
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

### 2. Input Validation
```python
import re

def validate_user_id(user_id):
    if not re.match(r'^\d+$', user_id):
        raise ValueError("Invalid user ID")
    return int(user_id)
```

### 3. Prepared Statements
```python
# Python with sqlite3
cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?",
               (username, password))
```

### 4. Stored Procedures
```sql
CREATE PROCEDURE GetUser(@userId INT)
AS
BEGIN
    SELECT * FROM users WHERE id = @userId
END
```

### 5. Least Privilege Principle
- Database user should have minimal permissions
- Separate read/write accounts
- No direct database access for web app

### XSS Prevention:

### 1. Output Encoding
```python
from html import escape
user_input = request.args.get('q', '')
safe_html = escape(user_input)  # Escapes < > & "
```

### 2. Content Security Policy (CSP)
```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'">
```

### 3. Input Sanitization
```python
import bleach

def sanitize_html(dirty_html):
    return bleach.clean(dirty_html, tags=[], strip=True)
```

### 4. Safe JavaScript Handling
```javascript
// Instead of eval() or innerHTML
element.textContent = userInput;  // Safe
element.innerHTML = escapeHtml(userInput);  // If HTML needed
```

### 5. HTTPOnly Cookies
```python
response.set_cookie('session', value, httponly=True)
```

### 6. Web Application Firewall (WAF)
- ModSecurity
- Cloudflare WAF
- AWS WAF

---

## 📚 Additional Learning Resources

### Free Online Courses:
- **OWASP WebGoat**: https://owasp.org/www-project-webgoat/
- **PortSwigger Web Security Academy**: https://portswigger.net/web-security
- **Cybrary**: https://www.cybrary.it/
- **TryHackMe**: https://tryhackme.com/

### Books:
- "Web Application Hacker's Handbook"
- "Hacking: The Art of Exploitation"
- "The Web Application Hacker's Handbook"

### Practice Platforms:
- **DVWA (Damn Vulnerable Web App)**
- **SQLi Labs**
- **HackTheBox**
- **VulnHub**

### Certifications:
- **CompTIA Security+**
- **CEH (Certified Ethical Hacker)**
- **OSCP (Offensive Security Certified Professional)**

---

## 🏆 Next Steps

1. **Master the Basics**: Understand how SQL injection works
2. **Learn Prevention**: Know how to write secure code
3. **Explore Other Vulnerabilities**:
   - XSS (Cross-Site Scripting)
   - CSRF (Cross-Site Request Forgery)
   - Command Injection
   - File Inclusion

4. **Practice Ethically**: Always get permission before testing
5. **Contribute**: Help make software more secure

---

## 🚨 Legal and Ethical Reminder

**Cybersecurity is about protection, not destruction.**

- Always obtain written permission before testing
- Respect privacy and data protection laws
- Report vulnerabilities responsibly
- Use your knowledge to help, not harm

**Happy Learning! 🛡️**

---

*This learning environment is for educational purposes only. The vulnerable application should never be deployed on public servers or used maliciously.*