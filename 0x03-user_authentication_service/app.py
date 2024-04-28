#!/usr/bin/env python3
"""Flask application
"""


from flask import Flask, abort, make_response, request, jsonify
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


@app.route('/sessions', methods=['POST'])
def login():
    # Retrieve email and password from form data
    email = request.form.get('email')
    password = request.form.get('password')

    # Verify login credentials
    if not AUTH.valid_login(email, password):
        # Incorrect login credentials
        abort(401)

    # If login is successful, create a new session
    session_id = AUTH.create_session(email)

    # Store session ID as a cookie in the response
    response = make_response(jsonify(
        {'message': 'Login successful', 'email': email}))
    response.set_cookie('session_id', session_id)

    return response


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
