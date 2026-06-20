# Intentionally vulnerable Flask app for testing SecureBuild
from flask import Flask, request, jsonify
import sqlite3
import pickle
import yaml
import subprocess
import hashlib
import os

app = Flask(__name__)

# VULNERABILITY: Hardcoded AWS Key
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# VULNERABILITY: Hardcoded password
DB_PASSWORD = "admin123"
SECRET_KEY = "hardcoded_flask_secret_key_12345"

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    # VULNERABILITY: SQL Injection (CWE-89)
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    if user:
        return jsonify({"status": "success"})
    return jsonify({"status": "failed"}), 401

@app.route('/execute', methods=['POST'])
def execute_command():
    cmd = request.form.get('cmd')
    # VULNERABILITY: Command Injection (CWE-78)
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return jsonify({"output": result.stdout})

@app.route('/eval', methods=['POST'])
def eval_expression():
    expr = request.form.get('expr')
    # VULNERABILITY: Code Injection via eval (CWE-95)
    result = eval(expr)
    return jsonify({"result": str(result)})

@app.route('/deserialize', methods=['POST'])
def deserialize_data():
    data = request.form.get('data')
    # VULNERABILITY: Insecure Deserialization (CWE-502)
    obj = pickle.loads(data.encode())
    return jsonify({"result": str(obj)})

@app.route('/parse-yaml', methods=['POST'])
def parse_yaml():
    data = request.form.get('data')
    # VULNERABILITY: Insecure YAML Loading (CWE-502)
    result = yaml.load(data)
    return jsonify({"result": str(result)})

@app.route('/hash', methods=['POST'])
def hash_password():
    password = request.form.get('password')
    # VULNERABILITY: Weak Hashing (CWE-327)
    hashed = hashlib.md5(password.encode()).hexdigest()
    return jsonify({"hash": hashed})

@app.route('/users/<user_id>')
def get_user(user_id):
    # VULNERABILITY: Path Traversal possible in user_id
    filepath = f"/var/data/users/{user_id}"
    with open(filepath, 'r') as f:
        return f.read()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
