#!/usr/bin/env python3
""" Auth module
"""
from typing import List

class Auth:
    """ Auth class for API authentication """
    
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Checks if authentication is required for a given path.

        Args:
            path: The path to check for authentication requirement.
            excluded_paths: List of paths excluded from authentication.

        Returns:
            True if authentication is required, False otherwise.
        """
        if path is None:
            return True

        if excluded_paths is None or not excluded_paths:
            return True

        # Append a trailing slash to the path for slash tolerance
        path = path.rstrip("/") + "/"

        return path not in excluded_paths

    def authorization_header(self, request=None) -> str:
        """
        Retrieves the Authorization header from the request.

        Args:
            request: Flask request object.

        Returns:
            The value of the Authorization header if present, otherwise None.
        """
        if request is None:
            return None

        return request.headers.get('Authorization')

    def current_user(self, request=None):
        """
        Placeholder method for retrieving the current user.
        
        Args:
            request: Flask request object.

        Returns:
            None.
        """
        return None
