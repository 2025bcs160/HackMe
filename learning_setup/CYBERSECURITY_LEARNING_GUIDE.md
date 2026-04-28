# Cybersecurity Learning Guide - SQL Injection

## 🎓 Welcome to Cybersecurity Learning!

This guide will help you learn about SQL injection vulnerabilities safely and ethically. We'll use intentionally vulnerable applications that you can test with your SQL injection scanner.

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
- Start a vulnerable web application on `http://localhost:5000`

### Step 2: Start the Vulnerable App

The setup script will automatically start the vulnerable application. You'll see:
```
🚨 LEARNING SQL INJECTION LAB 🚨
Starting server on http://localhost:5000
```

### Step 3: Test with Your Scanner

Now use your SQL injection scanner on the local app:

```batch
# Test URL parameters
python main.py scan-url --url "http://localhost:5000/search?id=1"

# Test login form
python main.py scan-form --url "http://localhost:5000/login" --data '{"username":"admin","password":"test"}'

# Test API endpoints
python main.py scan-json-api --url "http://localhost:5000/api/search" --json-data '{"query":"admin","table":"users"}'
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

### 2. Types of SQL Injection

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

---

## 🔍 Analyzing Your Results

### What to Look For:

1. **Unexpected Data**: If you see other users' information
2. **Database Errors**: Messages like "SQL syntax error"
3. **Bypassed Authentication**: Logging in without correct password
4. **Information Disclosure**: Database version, table names, etc.

### Common Payloads to Try:

```
' OR '1'='1
' OR 1=1 --
admin' --
' UNION SELECT NULL --
' AND SLEEP(5) --
```

---

## 🛡️ Prevention Techniques

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

### 5. Web Application Firewall (WAF)
- ModSecurity
- Cloudflare WAF
- AWS WAF

### 6. Least Privilege Principle
- Database user should have minimal permissions
- Separate read/write accounts
- No direct database access for web app

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