#!/usr/bin/env python3
"""
Auth module
"""
import bcrypt
import uuid
from flask import abort, app, redirect, request
from app import AUTH
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a new user
        """
        # Check if user already exists
        try:
            existing_user = self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:  # type: ignore
            pass   # User does not exist, continue with registration

        # Hash the password
        hashed_password = self._hash_password(password)

        # Save user to the database
        user = self._db.add_user(email=email, hashed_password=hashed_password)

        return user

    def valid_login(self, email: str, password: str) -> bool:
        """Check if login credentials are valid"""
        try:
            user = self._db.find_user_by(email=email)
            hashed_password = user.hashed_password.encode('utf-8')
            return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
        except ValueError:
            # Handle ValueError if user is not found
            return False
        except Exception as e:
            # Handle other exceptions
            print(f"An error occurred: {e}")
            return False

    def _generate_uuid(self) -> str:
        """Generate a string representation of a new UUID.

        Returns:
            str: A string representation of a new UUID.
        """
        return str(uuid.uuid4())

    def create_session(self, email: str) -> str:
        """Create a session for the user with the given email.

        Args:
            email (str): The email of the user.

        Returns:
            str: The session ID.
        """
        # Find the user corresponding to the email
        user = self._db.find_user_by(email=email)

        # Generate a new session ID
        session_id = self._generate_uuid()

        # Update the user's session ID in the database
        self._db.update_user(user, session_id=session_id)

        # Return the session ID
        return session_id

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
        user = AUTH.get_user_from_session_id(session_id)

        if user is not None:
            # Destroy the session
            AUTH.destroy_session(user.id)

            # Redirect user to GET /
            return redirect('/')
        else:
            # User does not exist, respond with 403
            abort(403)

    def get_reset_password_token(self, email: str) -> str:
        """Generate a reset password token
        for the user with the provided email.

        Args:
            email (str): The email of the user.

        Returns:
            str: The reset password token.

        Raises:
            ValueError: If no user is found with the provided email.
        """
        # Find the user corresponding to the email
        user = self._db.find_user_by(email=email)

        if user is None:
            # If no user found, raise ValueError
            raise ValueError(f"No user found with email {email}")

        # Generate a UUID for the reset password token
        reset_token = str(uuid.uuid4())

        # Update the user's reset_token field in the database
        self._db.update_user(user, reset_token=reset_token)

        # Return the generated token
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Update user's password using reset token.

        Args:
            reset_token (str): Reset token string.
            password (str): New password string.

        Raises:
            ValueError: If the reset token does not correspond to any user.
        """
        # Find the user corresponding to the reset token
        user = self._db.find_user_by(reset_token=reset_token)

        if user is None:
            # If user is not found, raise ValueError
            raise ValueError("Invalid reset token")

        # Hash the new password
        hashed_password = self._hash_password(password)

        # Update user's hashed password and reset token fields
        self._db.update_user(
            user, hashed_password=hashed_password, reset_token=None)
