#!/usr/bin/env python3
"""Redacting Formatter module"""
import logging
import re


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class"""

    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields):
        super().__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        def filter_datum(fields, redaction, message, separator):
            return re.sub(
                r'(?<=^|{})(?:{})(?={}|$)'.format
                (separator, '|'.join(map(re.escape, fields))),
                redaction,
                message
            )
        message = super().format(record)
        return filter_datum(self.fields, '***', message, self.SEPARATOR)
