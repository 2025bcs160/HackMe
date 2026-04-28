#!/usr/bin/env python3
"""
Simple Vulnerable Web Application for SQL Injection Learning
This is a deliberately vulnerable application for educational purposes ONLY
"""

from flask import Flask, request, jsonify
import sqlite3
import os

app = Flask(__name__)

def init_db():
    """Initialize the database with sample data"""
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()

    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT,
                    password TEXT,
                    email TEXT
                )''')

    # Create products table
    c.execute('''CREATE TABLE IF NOT EXISTS products (
                    id INTEGER PRIMARY KEY,
                    name TEXT,
                    price REAL,
                    category TEXT
                )''')

    # Insert sample data
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'password123', 'admin@example.com')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'userpass', 'user@example.com')")
    c.execute("INSERT OR IGNORE INTO users VALUES (3, 'test', 'test123', 'test@example.com')")

    c.execute("INSERT OR IGNORE INTO products VALUES (1, 'Laptop', 999.99, 'Electronics')")
    c.execute("INSERT OR IGNORE INTO products VALUES (2, 'Book', 19.99, 'Education')")
    c.execute("INSERT OR IGNORE INTO products VALUES (3, 'Phone', 599.99, 'Electronics')")

    conn.commit()
    conn.close()

@app.route('/')
def home():
    return """
    <h1>Learning SQL Injection Lab</h1>
    <p>This is a deliberately vulnerable web application for learning purposes.</p>
    <p><strong>⚠️ WARNING: This app is intentionally insecure!</strong></p>
    <ul>
        <li><a href="/search?id=1">Search by ID (Vulnerable)</a></li>
        <li><a href="/login">Login Form</a></li>
        <li><a href="/api/users/1">API - Get User</a></li>
        <li><a href="/api/products">API - Get Products</a></li>
    </ul>
    """

@app.route('/search')
def search():
    """VULNERABLE: Direct SQL injection in URL parameter"""
    user_id = request.args.get('id', '1')

    # VULNERABLE CODE - NEVER DO THIS IN PRODUCTION!
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()

    # This is the vulnerable query - it directly concatenates user input
    query = f"SELECT * FROM users WHERE id = {user_id}"
    print(f"[DEBUG] Executing query: {query}")  # For learning purposes

    try:
        c.execute(query)
        results = c.fetchall()
        conn.close()

        if results:
            user = results[0]
            return f"""
            <h2>User Found</h2>
            <p>ID: {user[0]}</p>
            <p>Username: {user[1]}</p>
            <p>Email: {user[3]}</p>
            <p><a href="/">Back to home</a></p>
            """
        else:
            return "<h2>No user found</h2><p><a href='/'>Back to home</a></p>"

    except Exception as e:
        return f"<h2>Database Error</h2><p>{str(e)}</p><p><a href='/'>Back to home</a></p>"

@app.route('/login', methods=['GET', 'POST'])
def login():
    """VULNERABLE: SQL injection in login form"""
    if request.method == 'GET':
        return """
        <h2>Login</h2>
        <form method="POST">
            <p>Username: <input type="text" name="username"></p>
            <p>Password: <input type="password" name="password"></p>
            <p><input type="submit" value="Login"></p>
        </form>
        <p><a href="/">Back to home</a></p>
        """

    username = request.form.get('username', '')
    password = request.form.get('password', '')

    # VULNERABLE CODE - NEVER DO THIS IN PRODUCTION!
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()

    # This is vulnerable to SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"[DEBUG] Login query: {query}")  # For learning purposes

    try:
        c.execute(query)
        results = c.fetchall()
        conn.close()

        if results:
            return f"""
            <h2>Login Successful!</h2>
            <p>Welcome, {results[0][1]}!</p>
            <p><a href="/">Back to home</a></p>
            """
        else:
            return """
            <h2>Login Failed</h2>
            <p>Invalid credentials</p>
            <p><a href="/">Back to home</a></p>
            """

    except Exception as e:
        return f"<h2>Database Error</h2><p>{str(e)}</p><p><a href='/'>Back to home</a></p>"

@app.route('/api/users/<user_id>')
def api_get_user(user_id):
    """VULNERABLE: SQL injection in API endpoint"""
    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()

    # VULNERABLE CODE
    query = f"SELECT id, username, email FROM users WHERE id = {user_id}"
    print(f"[DEBUG] API query: {query}")  # For learning purposes

    try:
        c.execute(query)
        results = c.fetchall()
        conn.close()

        if results:
            user = results[0]
            return jsonify({
                'id': user[0],
                'username': user[1],
                'email': user[2]
            })
        else:
            return jsonify({'error': 'User not found'}), 404

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/products')
def api_get_products():
    """VULNERABLE: SQL injection in API with JSON parameters"""
    category = request.args.get('category', '')
    limit = request.args.get('limit', '10')

    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()

    # VULNERABLE CODE
    query = f"SELECT * FROM products WHERE category LIKE '%{category}%' LIMIT {limit}"
    print(f"[DEBUG] Products query: {query}")  # For learning purposes

    try:
        c.execute(query)
        results = c.fetchall()
        conn.close()

        products = []
        for product in results:
            products.append({
                'id': product[0],
                'name': product[1],
                'price': product[2],
                'category': product[3]
            })

        return jsonify(products)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/search', methods=['POST'])
def api_search():
    """VULNERABLE: SQL injection in JSON POST data"""
    data = request.get_json()

    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400

    search_term = data.get('query', '')
    table = data.get('table', 'users')

    conn = sqlite3.connect('vulnerable.db')
    c = conn.cursor()

    # VULNERABLE CODE - allows table selection too!
    query = f"SELECT * FROM {table} WHERE username LIKE '%{search_term}%' OR name LIKE '%{search_term}%'"
    print(f"[DEBUG] Search query: {query}")  # For learning purposes

    try:
        c.execute(query)
        results = c.fetchall()
        conn.close()

        return jsonify({'results': results})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    init_db()
    print("=" * 50)
    print("🚨 LEARNING SQL INJECTION LAB 🚨")
    print("=" * 50)
    print("This app is INTENTIONALLY VULNERABLE!")
    print("Use it ONLY for learning cybersecurity.")
    print()
    print("Starting server on http://localhost:5000")
    print("Press Ctrl+C to stop")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)