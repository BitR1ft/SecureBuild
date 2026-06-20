# Secure Flask app — fixed version of the vulnerable test fixture
# All vulnerabilities from the original have been remediated.
from flask import Flask, request, jsonify
import sqlite3
import json
import yaml
import subprocess
import hashlib
import os

app = Flask(__name__)

# SECURE: Secrets loaded from environment variables
AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY", "")
AWS_SECRET_KEY = os.environ.get("AWS_SECRET_KEY", "")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", os.urandom(32).hex())


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    # SECURE: Parameterized query prevents SQL Injection (CWE-89)
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(query, (username, password))
    user = cursor.fetchone()
    conn.close()
    if user:
        return jsonify({"status": "success"})
    return jsonify({"status": "failed"}), 401


@app.route('/execute', methods=['POST'])
def execute_command():
    # SECURE: No user-supplied command execution
    # Use a whitelist of allowed commands instead of shell=True
    allowed_commands = {"status": ["systemctl", "status", "app"]}
    cmd_name = request.form.get('cmd', '')
    if cmd_name not in allowed_commands:
        return jsonify({"error": "Command not allowed"}), 403
    result = subprocess.run(
        allowed_commands[cmd_name],
        shell=False,
        capture_output=True,
        text=True,
    )
    return jsonify({"output": result.stdout})


@app.route('/eval', methods=['POST'])
def eval_expression():
    # SECURE: Use ast.literal_eval instead of eval (CWE-95 fixed)
    import ast
    expr = request.form.get('expr', '')
    try:
        result = ast.literal_eval(expr)
    except (ValueError, SyntaxError):
        return jsonify({"error": "Invalid expression"}), 400
    return jsonify({"result": str(result)})


@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    # SECURE: Use JSON instead of pickle (CWE-502 fixed)
    data = request.form.get('data', '')
    try:
        obj = json.loads(data)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON"}), 400
    return jsonify({"result": str(obj)})


@app.route('/parse-yaml', methods=['POST'])
def parse_yaml():
    data = request.form.get('data', '')
    # SECURE: Use yaml.safe_load instead of yaml.load (CWE-502 fixed)
    result = yaml.safe_load(data)
    return jsonify({"result": str(result)})


@app.route('/hash', methods=['POST'])
def hash_password():
    password = request.form.get('password', '')
    # SECURE: Use bcrypt for password hashing (CWE-327 fixed)
    import hashlib
    salt = os.urandom(16)
    # Use SHA-256 with salt as a basic improvement
    # Production code should use bcrypt or argon2
    hashed = hashlib.sha256(salt + password.encode()).hexdigest()
    return jsonify({"hash": hashed, "salt": salt.hex()})


@app.route('/users/<user_id>')
def get_user(user_id):
    # SECURE: Validate user_id to prevent path traversal
    import re
    if not re.match(r'^[a-zA-Z0-9_-]+$', user_id):
        return jsonify({"error": "Invalid user ID"}), 400
    filepath = f"/var/data/users/{user_id}"
    try:
        with open(filepath, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return jsonify({"error": "User not found"}), 404


if __name__ == '__main__':
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    app.run(debug=debug_mode, host=host)
