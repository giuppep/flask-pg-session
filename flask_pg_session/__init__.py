"""``FlaskPgSession`` is a `Flask <https://flask.palletsprojects.com/>`_  extensions \
that implements server-side session support and stores the data in a PostgreSQL table.

It is inspired by `Flask-Session <https://flasksession.readthedocs.io/en/latest/>`_,
but it's focused only on integration with PostgreSQL and therefore has fewer
dependencies.

It is intended for people that are already using Flask with PostgreSQL and do not want
to add another dependency to their app just for storing sessions (e.g. Redis).
"""
from .session import FlaskPgSession

__all__ = ["FlaskPgSession"]
