"""
Deliberately Vulnerable Python App — for testing the RLM scanner.
DO NOT deploy this in production!
"""
import hashlib
import os
import sqlite3

# !! CRITICAL: Hardcoded credentials
DB_PASSWORD = "SuperSecret123!"
# !! CRITICAL: Hardcoded API Key
API_KEY = "sk-prod-" + "AbCdEfGhIjKlMnOpQrStUvWx1234567890"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29Bz1dF
-----END RSA PRIVATE KEY-----"""

conn = sqlite3.connect("users.db")
cursor = conn.cursor()

# !! HIGH: SQL Injection via f-string
def get_user(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()

# !! HIGH: SQL Injection via concatenation
def search_users(query):
    sql = "SELECT * FROM users WHERE name = '" + query + "'"
    cursor.execute(sql)
    return cursor.fetchall()

# !! HIGH: SQL Injection via string formatting
def login(username, password):
    cursor.execute("SELECT * FROM users WHERE user='%s' AND pass='%s'" % (username, password))
    return cursor.fetchone()

# !! HIGH: Crypto misuse — MD5 for passwords
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

# !! HIGH: Crypto misuse — SHA1
def verify_integrity(data):
    return hashlib.sha1(data).hexdigest()

# !! HIGH: Path traversal via open() with user input
def read_file(request_path):
    # Simulating a web request parameter
    return open(request_path, "r").read()

# !! HIGH: Path traversal via os.path.join
def serve_file(base_dir, user_input):
    path = os.path.join(base_dir, user_input)
    with open(path, "rb") as f:
        return f.read()
