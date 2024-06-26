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

    def find_user_by(self, **kwargs) -> User:
        """
        Find user based on keyword arguments
        """
        try:
            record = self._session.query(User).filter_by(**kwargs).first()
        except TypeError:
            raise InvalidRequestError
        if record is None:
            raise NoResultFound
        return record

    def update_user(self, user_id: int, **kwargs) -> None:
        """
        Update user based on user_id and keyword arguments
        """
        user = self.find_user_by(id=user_id)
        for key, value in kwargs.items():
            if not hasattr(user, key):
                raise ValueError
            setattr(user, key, value)
        self._session.commit()
