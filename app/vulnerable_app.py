import sqlite3
import subprocess
from flask import Flask, request

app = Flask(__name__)

# Issue 1: Hardcoded Secret
API_SECRET_KEY = "AIzaSyD-TESTING-SECRET-TOKEN-DO-NOT-USE"

@app.route("/user")
def get_user():
    username = request.args.get("username")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Issue 2: SQL Injection
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()

@app.route("/ping")
def ping_host():
    host = request.args.get("host")
    # Issue 3: Command Injection
    cmd = f"ping -c 1 {host}"
    output = subprocess.check_output(cmd, shell=True)
    return output

if __name__ == "__main__":
    app.run(debug=True)
# Test PR Trigger
