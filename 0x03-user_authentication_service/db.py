#!/usr/bin/env python3
"""
Database module
"""

import logging

from sqlite3 import IntegrityError
from sqlalchemy import create_engine  # type: ignore
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound

from user import Base, User
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import InvalidRequestError  # type: ignore

# Disable all logging messages
logging.disable(logging.CRITICAL)


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=True)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self):
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Add a new user to the database
        """
        user = User(email=email, hashed_password=hashed_password)
        self._session.add(user)
        try:
            self._session.commit()
        except IntegrityError:
            self._session.rollback()
            raise ValueError("User already exists with this email")
        return user

    def find_user_by(self, **kwargs):
        """Find a user by filtering rows based on input keyword arguments
        """
        try:
            user = self._session.query(User).filter_by(**kwargs).first()
            if user is None:
                raise NoResultFound\
                    ("No user found with the specified criteria")
            return user
        except NoResultFound:
            raise  # Re-raise NoResultFound
        except InvalidRequestError as e:
            raise InvalidRequestError("Invalid query arguments") from e

    def update_user(self, user_id: int, **kwargs):
        """
        Updates the user's attributes as passed in the method’s
        arguments and commits changes to the database.
        """
        user = self.find_user_by(id=user_id)

        for key, value in kwargs.items():
            if hasattr(user, key):
                setattr(user, key, value)
            else:
                raise ValueError(f"Invalid attribute: {key}")

        self._session.commit()
