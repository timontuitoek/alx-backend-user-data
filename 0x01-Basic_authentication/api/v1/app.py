#!/usr/bin/env python3
""" Main app module"""

from os import getenv
from api.v1.views import app_views
from flask import Flask, jsonify, abort, request
from flask_cors import CORS

# Import Auth class from auth module
from api.v1.auth.auth import Auth

# Create Flask app
app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})

# Initialize auth variable based on AUTH_TYPE environment variable
auth = None
auth_type = getenv("AUTH_TYPE")
if auth_type:
    if auth_type == "basic_auth":
        from api.v1.auth.auth import Auth as BasicAuth
        auth = BasicAuth()

# Define error handlers
@app.errorhandler(404)
def not_found(error):
    """ Not found handler """
    return jsonify({"error": "Not found"}), 404

@app.errorhandler(401)
def unauthorized(error):
    """ Unauthorized handler """
    return jsonify({"error": "Unauthorized"}), 401

@app.errorhandler(403)
def forbidden(error):
    """ Forbidden handler """
    return jsonify({"error": "Forbidden"}), 403

# Define before_request handler
@app.before_request
def before_request():
    """ Handles request filtering and authorization """
    if auth is None:
        return

    excluded_paths = ['/api/v1/status/', '/api/v1/unauthorized/', '/api/v1/forbidden/']
    if request.path in excluded_paths:
        return

    if not auth.require_auth(request.path, excluded_paths):
        return

    if auth.authorization_header(request) is None:
        abort(401)

    if auth.current_user(request) is None:
        abort(403)

if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port)