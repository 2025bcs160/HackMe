#!/usr/bin/env python3
"""
Vulnerable XSS Testing Application
This app contains various XSS vulnerabilities for learning purposes ONLY
"""

from flask import Flask, request, jsonify, render_template_string
import json

app = Flask(__name__)

# In-memory storage for stored XSS demo
comments = []
messages = []

@app.route('/')
def home():
    return render_template_string("""
    <html>
    <head><title>XSS Learning Lab</title></head>
    <body>
        <h1>🚨 XSS Learning Lab 🚨</h1>
        <p><strong>WARNING: This app is intentionally vulnerable!</strong></p>
        <p>Use it ONLY for learning cybersecurity.</p>

        <h2>Test Cases:</h2>
        <ul>
            <li><a href="/reflected?q=test">Reflected XSS - URL Parameter</a></li>
            <li><a href="/stored">Stored XSS - Comments</a></li>
            <li><a href="/dom#test">DOM-based XSS - URL Fragment</a></li>
            <li><a href="/search">Search with XSS</a></li>
            <li><a href="/contact">Contact Form</a></li>
        </ul>

        <h2>API Endpoints:</h2>
        <ul>
            <li><a href="/api/search?q=test">API Search</a></li>
            <li><a href="/api/messages">API Messages</a></li>
        </ul>
    </body>
    </html>
    """)

@app.route('/reflected')
def reflected_xss():
    """VULNERABLE: Reflected XSS in URL parameter"""
    query = request.args.get('q', '')

    # VULNERABLE: Direct output without sanitization
    html = f"""
    <html>
    <head><title>Reflected XSS Test</title></head>
    <body>
        <h1>Search Results</h1>
        <p>You searched for: {query}</p>
        <form method="GET">
            <input type="text" name="q" value="{query}" placeholder="Search...">
            <input type="submit" value="Search">
        </form>
        <p><a href="/">Back to home</a></p>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route('/stored', methods=['GET', 'POST'])
def stored_xss():
    """VULNERABLE: Stored XSS in comments"""
    if request.method == 'POST':
        name = request.form.get('name', '')
        comment = request.form.get('comment', '')

        # VULNERABLE: Store without sanitization
        comments.append({'name': name, 'comment': comment})

    # Display all comments (VULNERABLE)
    comments_html = ""
    for i, c in enumerate(comments):
        comments_html += f"<div><strong>{c['name']}:</strong> {c['comment']}</div>"

    html = f"""
    <html>
    <head><title>Stored XSS Test</title></head>
    <body>
        <h1>Comments</h1>

        <form method="POST">
            <p>Name: <input type="text" name="name"></p>
            <p>Comment: <textarea name="comment"></textarea></p>
            <p><input type="submit" value="Post Comment"></p>
        </form>

        <h2>All Comments:</h2>
        {comments_html}

        <p><a href="/">Back to home</a></p>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route('/dom')
def dom_xss():
    """VULNERABLE: DOM-based XSS"""
    html = """
    <html>
    <head><title>DOM XSS Test</title></head>
    <body>
        <h1>DOM-based XSS Test</h1>
        <p>Check the URL fragment (after #) - it gets processed by JavaScript!</p>

        <div id="output"></div>

        <script>
            // VULNERABLE: Direct use of location.hash
            var hash = location.hash.substring(1);
            if (hash) {
                document.getElementById('output').innerHTML = hash;
            } else {
                document.getElementById('output').innerHTML = 'No fragment found. Try adding #&lt;script&gt;alert("XSS")&lt;/script&gt;';
            }
        </script>

        <p><a href="/">Back to home</a></p>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route('/search')
def search_xss():
    """VULNERABLE: XSS in search functionality"""
    term = request.args.get('term', '')

    # VULNERABLE: Direct output
    html = f"""
    <html>
    <head><title>Search</title></head>
    <body>
        <h1>Search Results</h1>
        <p>Results for: <strong>{term}</strong></p>

        <form method="GET">
            <input type="text" name="term" value="{term}" placeholder="Search...">
            <input type="submit" value="Search">
        </form>

        <p><a href="/">Back to home</a></p>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route('/contact', methods=['GET', 'POST'])
def contact_xss():
    """VULNERABLE: XSS in contact form"""
    if request.method == 'POST':
        name = request.form.get('name', '')
        email = request.form.get('email', '')
        message = request.form.get('message', '')

        # VULNERABLE: Store message without sanitization
        messages.append({'name': name, 'email': email, 'message': message})

        return render_template_string(f"""
        <html>
        <head><title>Thank You</title></head>
        <body>
            <h1>Thank you for your message!</h1>
            <p>Name: {name}</p>
            <p>Email: {email}</p>
            <p>Message: {message}</p>
            <p><a href="/">Back to home</a></p>
        </body>
        </html>
        """)

    html = """
    <html>
    <head><title>Contact Form</title></head>
    <body>
        <h1>Contact Us</h1>
        <form method="POST">
            <p>Name: <input type="text" name="name"></p>
            <p>Email: <input type="email" name="email"></p>
            <p>Message: <textarea name="message"></textarea></p>
            <p><input type="submit" value="Send"></p>
        </form>
        <p><a href="/">Back to home</a></p>
    </body>
    </html>
    """
    return render_template_string(html)

@app.route('/api/search')
def api_search_xss():
    """VULNERABLE: XSS in JSON API response"""
    query = request.args.get('q', '')

    # VULNERABLE: Return unsanitized data
    return jsonify({
        'query': query,
        'results': [f'Result for: {query}'],
        'html': f'<div>Search results: {query}</div>'  # This could be dangerous if rendered
    })

@app.route('/api/messages', methods=['GET', 'POST'])
def api_messages_xss():
    """VULNERABLE: XSS in JSON API with stored data"""
    if request.method == 'POST':
        data = request.get_json()
        if data:
            messages.append(data)

    # VULNERABLE: Return all messages without sanitization
    return jsonify({'messages': messages})

if __name__ == '__main__':
    print("=" * 50)
    print("🚨 XSS LEARNING LAB 🚨")
    print("=" * 50)
    print("This app is INTENTIONALLY VULNERABLE!")
    print("Use it ONLY for learning cybersecurity.")
    print()
    print("Vulnerabilities included:")
    print("- Reflected XSS (URL parameters)")
    print("- Stored XSS (forms/comments)")
    print("- DOM-based XSS (URL fragments)")
    print("- API XSS (JSON responses)")
    print()
    print("Starting server on http://localhost:5001")
    print("Press Ctrl+C to stop")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5001)