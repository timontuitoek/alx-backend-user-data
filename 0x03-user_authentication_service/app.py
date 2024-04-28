#!/usr/bin/env python3
"""Flask application
"""


from flask import Flask, abort, make_response, redirect, request, jsonify
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route('/')
def index() -> str:
    """ GET /
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def register_user():
    email = request.form.get("email")
    password = request.form.get("password")

    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email": user.email, "message": "user created"}), 200
    except ValueError as e:
        return jsonify({"message": str(e)}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login() -> str:
    """ POST /sessions
    Creates new session for user, stores as cookie
    Email and pswd fields in x-www-form-urlencoded request
    Return:
      - JSON payload
    """
    email = request.form.get("email")
    password = request.form.get("password")
    valid_user = AUTH.valid_login(email, password)

    if not valid_user:
        abort(401)
    session_id = AUTH.create_session(email)
    message = {"email": email, "message": "logged in"}
    response = jsonify(message)
    response.set_cookie("session_id", session_id)
    return response


@app.route("/sessions", methods=["DELETE"], strict_slashes=False)
def logout() -> str:
    """DELETE /sessions
    Return:
        - Redirects to home route.
    """
    session_id = request.cookies.get("session_id")
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect("/")


@app.route("/reset_password", methods=["POST"])
def get_reset_password_token():
    # Get the email from the request form data
    email = request.form.get("email")

    try:
        # Try to generate a reset password token
        reset_token = AUTH.get_reset_password_token(email)
    except ValueError:
        # If email is not registered, respond with 403 status code
        abort(403)

    # If email is registered, respond with 200 status code and JSON payload
    return jsonify({"email": email, "reset_token": reset_token}), 200


@app.route('/reset_password', methods=['PUT'])
def update_password():
    """Update user's password."""
    # Get form data from the request
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_password = request.form.get('new_password')

    try:
        # Attempt to update the password
        AUTH.update_password(reset_token, new_password)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except ValueError:
        # If the token is invalid, respond with a 403 HTTP code
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
