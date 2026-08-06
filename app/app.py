import os
import pickle
import sqlite3
import subprocess
import yaml
from flask import Flask, make_response, request, send_file, render_template_string

app = Flask(__name__)

# 1. Hardcoded Secret / API Key
SECRET_KEY = "super-secret-admin-key-12345" 

# 2. Hardcoded Database Credentials
DB_USER = "root"
DB_PASS = "toor123"

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")
    
    # 3. SQL Injection via string formatting
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    if user:
        resp = make_response("Logged in")
        # 4. Insecure Cookie (Missing Secure and HttpOnly flags)
        resp.set_cookie("session_id", str(user[0]))
        return resp
    return "Bad login"

@app.route("/run")
def run_command():
    # 5. OS Command Injection
    cmd = request.args.get("cmd", "echo hello")
    # 6. Use of shell=True in subprocess
    output = subprocess.check_output(cmd, shell=True)
    return output

@app.route("/calc")
def calculate():
    # 7. Arbitrary Code Execution via eval()
    expr = request.args.get("expr", "0")
    return str(eval(expr))

@app.route("/load-config", methods=["POST"])
def load_config():
    data = request.form.get("yaml_data")
    # 8. Unsafe YAML Loading (PyYAML)
    config = yaml.load(data, Loader=yaml.Loader)
    return str(config)

@app.route("/deserialize", methods=["POST"])
def deserialize():
    # 9. Insecure Deserialization via pickle
    payload = request.data
    obj = pickle.loads(payload)
    return str(obj)

@app.route("/download")
def download_file():
    # 10. Path Traversal
    filename = request.args.get("file")
    return send_file(os.path.join("/var/www/uploads", filename))

@app.route("/greet")
def greet():
    # 11. Server-Side Template Injection (SSTI)
    name = request.args.get("name", "Guest")
    template = f"Hello <h1>{name}</h1>"
    return render_template_string(template)

@app.route("/debug")
def debug_info():
    # 12. Information Disclosure (Exposing environment/config details)
    return str(os.environ)

if __name__ == "__main__":
    # Debug mode enabled in production-like layout
    app.run(debug=True, host="0.0.0.0")