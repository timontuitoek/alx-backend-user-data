#!/usr/bin/env python3
"""
Auth module
"""
import bcrypt
import uuid
from flask import abort, app, redirect, request

from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from flask import Flask

app = Flask(__name__)


def _hash_password(password: str) -> bytes:
    """
    Hashes a password
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def _generate_uuid() -> str:
    """
    Generates a UUID
    """
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    @app.route('/sessions', methods=['DELETE'])
    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """ Registers and returns a new user if email isn't listed"""
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hashed_password = _hash_password(password)
            new_user = self._db.add_user(email, hashed_password)
            return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """ Check valid login """
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(
                password.encode('utf-8'),
                user.hashed_password
                )
        except NoResultFound:
            return False

    def _generate_uuid(self) -> str:
        """Generate a string representation of a new UUID.

        Returns:
            str: A string representation of a new UUID.
        """
        return str(uuid.uuid4())

    def create_session(self, email: str) -> str:
        """ Create session """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str):
        """Get the user corresponding to the session ID.

        Args:
            session_id (str): The session ID.

        Returns:
            User or None: The corresponding user if found, otherwise None.
        """
        if session_id is None:
            return None

        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroy the session for the given user ID.

        Args:
            user_id (int): The ID of the user.

        Returns:
            None
        """
        self._db.update_user(user_id=user_id, session_id=None)

    @app.route('/sessions', methods=['DELETE'])
    def logout():
        # Extract session ID from request cookies
        session_id = request.cookies.get('session_id')

        # Find user corresponding to the session ID
        user = AUTH.get_user_from_session_id(session_id)  # type: ignore

        if user is not None:
            # Destroy the session
            AUTH.destroy_session(user.id)  # type: ignore

            # Redirect user to GET /
            return redirect('/')
        else:
            # User does not exist, respond with 403
            abort(403)

    def get_reset_password_token(self, email: str) -> str:
        """Generates a password reset token for a user.
        """
        user = None
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            user = None
        if user is None:
            raise ValueError()
        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates a user's password given the user's reset token.
        """
        user = None
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            user = None
        if user is None:
            raise ValueError()
        new_password_hash = _hash_password(password)
        self._db.update_user(
            user.id,
            hashed_password=new_password_hash,
            reset_token=None,
        )
