import sqlite3
from flask import Flask, request

app = Flask(__name__)

conn = sqlite3.connect("users.db", check_same_thread=False)

@app.route("/user")
def user():
    user_id = request.args.get("id")

    query = "SELECT * FROM users WHERE id = " + user_id

    cursor = conn.cursor()

    cursor.execute(query)

    return "Done"

if __name__ == "__main__":
    app.run()