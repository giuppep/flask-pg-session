from __future__ import annotations

import logging
import pickle
import random
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Generator, Optional
from uuid import uuid4

from flask import Flask, Request, Response
from flask.sessions import SessionInterface as FlaskSessionInterface
from flask.sessions import SessionMixin
from itsdangerous import BadSignature, Signer, want_bytes
from psycopg2.extensions import connection as PsycoPg2Connection
from psycopg2.extensions import cursor as PsycoPg2Cursor
from psycopg2.pool import ThreadedConnectionPool
from werkzeug.datastructures import CallbackDict

from ._queries import Queries
from .utils import retry_query

logger = logging.getLogger(__name__)

DEFAULT_TABLE_NAME = "flask_sessions"
DEFAULT_SCHEMA_NAME = "public"
DEFAULT_KEY_PREFIX = ""
DEFAULT_USE_SIGNER = False
DELETE_EXPIRED_SESSIONS_EVERY_REQUESTS = 1000


# This is copied verbatim from flask-session
class ServerSideSession(CallbackDict, SessionMixin):
    """Baseclass for server-side based sessions."""

    def __init__(
        self,
        initial: dict[str, Any] | None = None,
        sid: str | None = None,
        permanent: bool | None = None,
    ) -> None:
        def on_update(self) -> None:  # type: ignore
            self.modified = True

        CallbackDict.__init__(self, initial, on_update)
        self.sid = sid
        if permanent:
            self.permanent = permanent
        self.modified = False


class FlaskPgSession(FlaskSessionInterface):
    # Can probably just use jsonb + orjson (fallback to json if not available)
    serializer = pickle
    session_class = ServerSideSession

    @classmethod
    def init_app(cls, app: Flask) -> "FlaskPgSession":
        """Initialize the Flask-PgSession extension using the app's configuration."""
        session_interface = cls(
            app.config["SQLALCHEMY_DATABASE_URI"],
            table_name=app.config.get("SESSION_PG_TABLE", DEFAULT_TABLE_NAME),
            schema_name=app.config.get("SESSION_PG_SCHEMA", DEFAULT_SCHEMA_NAME),
            key_prefix=app.config.get("SESSION_KEY_PREFIX", DEFAULT_KEY_PREFIX),
            use_signer=app.config.get("SESSION_USE_SIGNER", DEFAULT_USE_SIGNER),
            permanent=app.config.get("SESSION_PERMANENT", True),
        )
        app.session_interface = session_interface
        return session_interface

    def __init__(
        self,
        uri: str,
        *,
        table_name: str = DEFAULT_TABLE_NAME,
        schema_name: str = DEFAULT_SCHEMA_NAME,
        key_prefix: str = DEFAULT_KEY_PREFIX,
        use_signer: bool = DEFAULT_USE_SIGNER,
        permanent: bool = True,
        autodelete_expired_sessions: bool = True,
        max_db_conn: int = 100,
    ) -> None:
        """Initialize a new Flask-PgSession instance.

        Args:
            uri (str): The database URI to connect to.
            table_name (str, optional): The name of the table to store sessions in.
                Defaults to "flask_sessions".
            schema_name (str, optional): The name of the schema to store sessions in.
                Defaults to "public".
            key_prefix (str, optional): The prefix to prepend to the session ID when
                storing it in the database. Defaults to "".
            use_signer (bool, optional): Whether to use a signer to sign the session.
                Defaults to False.
            permanent (bool, optional): Whether the session should be permanent.
                Defaults to True.
            autodelete_expired_sessions (bool, optional): Whether to automatically
                delete expired sessions. Defaults to True.
            max_db_conn (int, optional): The maximum number of database connections to
                keep open. Defaults to 100.
        """
        self.pool = ThreadedConnectionPool(1, max_db_conn, uri)
        self.key_prefix = key_prefix

        self.permanent = permanent
        self.use_signer = use_signer
        self.has_same_site_capability = hasattr(self, "get_cookie_samesite")

        self.autodelete_expired_sessions = autodelete_expired_sessions

        self._queries = Queries(schema_name, table_name)

        self._create_schema_and_table()

    # HELPERS

    def _generate_sid(self) -> str:
        return str(uuid4())

    def _get_signer(self, app: Flask) -> Signer | None:
        if not app.secret_key:
            return None
        return Signer(app.secret_key, salt="flask-session", key_derivation="hmac")

    def _unsign_sid(self, app: Flask, sid: str) -> str:
        signer = self._get_signer(app)
        if not self.use_signer or not signer:
            raise RuntimeError("Session signing is disabled.")

        return signer.unsign(sid).decode()

    def _sign_sid(self, app: Flask, sid: str) -> str:
        signer = self._get_signer(app)
        if not self.use_signer or not signer:
            raise RuntimeError("Session signing is disabled.")

        return signer.sign(want_bytes(sid)).decode()

    def _get_store_id(self, sid: str) -> str:
        return self.key_prefix + sid

    # QUERY HELPERS

    @contextmanager
    def _get_cursor(
        self, conn: Optional[PsycoPg2Connection] = None
    ) -> Generator[PsycoPg2Cursor, None, None]:
        _conn: PsycoPg2Connection = conn or self.pool.getconn()

        assert isinstance(_conn, PsycoPg2Connection)
        try:
            with _conn:
                with _conn.cursor() as cur:
                    yield cur
        except Exception:
            raise
        finally:
            self.pool.putconn(_conn)

    @retry_query(max_attempts=3)
    def _create_schema_and_table(self) -> None:
        with self._get_cursor() as cur:
            cur.execute(self._queries.create_schema)
            cur.execute(self._queries.create_table)

    def _delete_expired_sessions(self) -> None:
        """Delete all expired sessions from the database."""
        with self._get_cursor() as cur:
            cur.execute(self._queries.delete_expired_sessions)

    @retry_query(max_attempts=3)
    def _delete_session(self, sid: str) -> None:
        with self._get_cursor() as cur:
            cur.execute(
                self._queries.delete_session,
                dict(session_id=self._get_store_id(sid)),
            )

    @retry_query(max_attempts=3)
    def _retrieve_session_data(self, sid: str) -> bytes | None:
        with self._get_cursor() as cur:
            cur.execute(
                self._queries.retrieve_session_data,
                dict(session_id=self._get_store_id(sid)),
            )
            data = cur.fetchone()

            return data[0] if data is not None else None

    @retry_query(max_attempts=3)
    def _update_session(
        self, sid: str, session: ServerSideSession, expires: datetime | None
    ) -> None:
        data = self.serializer.dumps(dict(session))

        # Remove timezone info from expires as the date is already in UTC and the
        #  timezone causes incorrect values to be stored in the database.
        expires = expires.replace(tzinfo=None) if expires else None

        with self._get_cursor() as cur:
            cur.execute(
                self._queries.upsert_session,
                dict(session_id=self._get_store_id(sid), data=data, expiry=expires),
            )

    # INTERFACE METHODS

    def open_session(self, app: Flask, request: Request) -> ServerSideSession:
        # Delete expired sessions approximately every N requests
        if (
            self.autodelete_expired_sessions
            and random.randint(0, DELETE_EXPIRED_SESSIONS_EVERY_REQUESTS) == 0
        ):
            app.logger.info("Deleting expired sessions")
            try:
                self._delete_expired_sessions()
            except Exception as e:
                app.logger.exception(
                    e, "Failed to delete expired sessions. Skipping..."
                )

        # Get the session ID from the cookie
        sid = request.cookies.get(self.get_cookie_name(app))

        # If there's no session ID, generate a new one
        if not sid:
            sid = self._generate_sid()
            return self.session_class(sid=sid, permanent=self.permanent)

        # If the session ID is signed, unsign it
        if self.use_signer:
            try:
                # This can fail, e.g. if the secret key was changed or if the signer
                #  was previously disabled.
                sid = self._unsign_sid(app, sid)
            except BadSignature:
                sid = self._generate_sid()
                return self.session_class(sid=sid, permanent=self.permanent)

        # Retrieve the session data from the database
        saved_session_data = self._retrieve_session_data(sid)

        if saved_session_data is not None:
            try:
                data = self.serializer.loads(want_bytes(saved_session_data))
                return self.session_class(data, sid=sid)
            except Exception:
                return self.session_class(sid=sid, permanent=self.permanent)
        return self.session_class(sid=sid, permanent=self.permanent)

    def save_session(
        self, app: Flask, session: SessionMixin, response: Response
    ) -> None:
        assert isinstance(session, ServerSideSession)
        assert session.sid is not None

        if not session:
            if session.modified:
                # If the session is empty and has been modified, delete it from the database
                self._delete_session(session.sid)
                # and delete the cookie
                response.delete_cookie(
                    self.get_cookie_name(app),
                    domain=self.get_cookie_domain(app),
                    path=self.get_cookie_path(app),
                )
            return

        # Respect SESSION_REFRESH_EACH_REQUEST preference
        if not self.should_set_cookie(app, session):
            return

        # Save the session to the database. If session is already present, update the
        #  data and expiry time.
        expires = self.get_expiration_time(app, session)
        self._update_session(session.sid, session, expires)

        cookie_session_id = (
            self._sign_sid(app, session.sid) if self.use_signer else session.sid
        )

        response.set_cookie(
            self.get_cookie_name(app),
            cookie_session_id,
            expires=expires,
            httponly=self.get_cookie_httponly(app),
            domain=self.get_cookie_domain(app),
            path=self.get_cookie_path(app),
            secure=self.get_cookie_secure(app),
            samesite=self.get_cookie_samesite(app)
            if self.has_same_site_capability
            else None,
        )
