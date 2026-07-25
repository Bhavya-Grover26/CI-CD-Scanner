from flask import Flask, request

app = Flask(__name__)

@app.route("/user")
def user():

    user_id = request.args.get("id")

    query = "SELECT * FROM users WHERE id = " + user_id

    return query

if __name__ == "__main__":
    app.run()
    