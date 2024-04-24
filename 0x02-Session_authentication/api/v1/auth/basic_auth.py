#!/usr/bin/env python3

import base64
from typing import Tuple
from api.v1.auth.auth import Auth
from models.user import User


class BasicAuth(Auth):
    """BasicAuth class for basic authentication"""

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """
        Extracts the Base64 part of the
        Authorization header for Basic Authentication.

        Args:
            authorization_header: The Authorization header value.

        Returns:
            The Base64 part of the
            Authorization header if valid, otherwise None.
        """
        if (authorization_header is None or
                not isinstance(authorization_header, str)):
            return None

        if not authorization_header.startswith("Basic "):
            return None

        return authorization_header.split(" ")[1]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
        Decodes a Base64 string into UTF-8 format.

        Args:
            base64_authorization_header: The Base64 string to decode.

        Returns:
            The decoded value as UTF-8 string, or None if the input is invalid.
        """
        if (base64_authorization_header is None or
                not isinstance(base64_authorization_header, str)):
            return None

        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            decoded_string = decoded_bytes.decode('utf-8')
            return decoded_string
        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> Tuple[str, str]:
        """
        Extracts user credentials from
        decoded Base64 authorization header.

        Args:
            decoded_base64_authorization_header:
            The decoded Base64 authorization header.

        Returns:
            A tuple containing the user email and password,
            or (None, None) if input is invalid.
        """
        if (decoded_base64_authorization_header is None or
                not isinstance(decoded_base64_authorization_header, str)):
            return None, None

        if ':' not in decoded_base64_authorization_header:
            return None, None

        parts = decoded_base64_authorization_header.split(':', 1)
        email = parts[0]
        password = parts[1]
        return email, password

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str):
        """
        Retrieves the User instance based on email and password.

        Args:
            user_email: The email of the user.
            user_pwd: The password of the user.

        Returns:
            The User instance if found and password is valid, otherwise None.
        """
        if (not isinstance(user_email, str) or
                not isinstance(user_pwd, str)):
            return None

        users = User.search({"email": user_email})
        if not users:
            return None

        user = users[0]
        if not user.is_valid_password(user_pwd):
            return None

        return user

    def current_user(self, request=None):
        """
        Retrieves the User instance for a request using Basic Authentication.

        Args:
            request: The Flask request object.

        Returns:
            The User instance if authenticated, otherwise None.
        """
        if request is None:
            return None

        auth_header = self.authorization_header(request)
        if auth_header is None:
            return None

        base64_auth_header = \
            self.extract_base64_authorization_header(auth_header)
        if base64_auth_header is None:
            return None

        decoded_auth_header = self.decode_base64_authorization_header(
            base64_auth_header)
        if decoded_auth_header is None:
            return None
