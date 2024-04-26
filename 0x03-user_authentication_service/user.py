#!/usr/bin/env python3

"""
Module: user.py
This module defines the User model for the users table.
"""


from sqlalchemy import Column, Integer, String  # type: ignore
from sqlalchemy.ext.declarative import declarative_base  # type: ignore


Base = declarative_base()


class User(Base):
    """
    Class representing a user in the database.
    """

    __tablename__ = 'users'

    id: int = Column(Integer, primary_key=True)
    email: str = Column(String(250), nullable=False)
    hashed_password: str = Column(String(250), nullable=False)
    session_id: str = Column(String(250), nullable=True)
    reset_token: str = Column(String(250), nullable=True)

    def __repr__(self):
        return f"<User(id={self.id}, email='{self.email}',\
        session_id='{self.session_id}',\
        reset_token='{self.reset_token}')>"
