from __future__ import annotations

import logging
import pickle
import random
from contextlib import contextmanager
from datetime import datetime
from typing import Generator, Optional
from uuid import uuid4

from flask import Flask, Request, Response
from flask.sessions import SessionInterface as FlaskSessionInterface
from flask.sessions import SessionMixin
from itsdangerous import BadSignature, Signer, want_bytes
from psycopg2.extensions import connection as PsycoPg2Connection
from psycopg2.extensions import cursor as PsycoPg2Cursor
from psycopg2.pool import ThreadedConnectionPool
from werkzeug.datastructures import CallbackDict

from .utils import retry_query

logger = logging.getLogger(__name__)

DEFAULT_TABLE_NAME = "flask_sessions"
DEFAULT_KEY_PREFIX = ""
DEFAULT_USE_SIGNER = False


# This is copied verbatim from flask-session
class ServerSideSession(CallbackDict, SessionMixin):
    """Baseclass for server-side based sessions."""

    def __init__(
        self, initial=None, sid: str | None = None, permanent: bool | None = None
    ):
        def on_update(self):
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
        session_interface = cls(
            app.config["SQLALCHEMY_DATABASE_URI"],
            table_name=app.config.get("SESSION_SQLALCHEMY_TABLE", DEFAULT_TABLE_NAME),
            key_prefix=app.config.get("SESSION_KEY_PREFIX", DEFAULT_KEY_PREFIX),
            use_signer=app.config.get("SESSION_USE_SIGNER", DEFAULT_USE_SIGNER),
        )
        app.session_interface = session_interface
        return session_interface

    def __init__(
        self,
        uri: str,
        *,
        table_name: str = DEFAULT_TABLE_NAME,
        key_prefix: str = DEFAULT_KEY_PREFIX,
        use_signer: bool = DEFAULT_USE_SIGNER,
        has_same_site_capability: bool = False,
        permanent: bool = True,
        autodelete_expired_sessions: bool = True,
        max_db_conn: int = 100,
    ) -> None:
        self.pool = ThreadedConnectionPool(1, max_db_conn, uri)
        self.key_prefix = key_prefix
        self.table_name = table_name
        self.permanent = permanent
        self.use_signer = use_signer
        self.has_same_site_capability = has_same_site_capability

        self.autodelete_expired_sessions = autodelete_expired_sessions

        self._create_table(self.table_name)

    def _generate_sid(self):
        return str(uuid4())

    def _get_signer(self, app: Flask) -> Signer | None:
        if not app.secret_key:
            return None
        return Signer(app.secret_key, salt="flask-session", key_derivation="hmac")

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

    def _get_store_id(self, sid: str) -> str:
        return self.key_prefix + sid

    @retry_query(max_attempts=3)
    def _create_table(self, table_name: str) -> None:
        with self._get_cursor() as cur:
            cur.execute(
                f"""CREATE TABLE IF NOT EXISTS {table_name} (
            session_id VARCHAR(255) NOT NULL PRIMARY KEY,
            created TIMESTAMP WITHOUT TIME ZONE DEFAULT (NOW() AT TIME ZONE 'utc'),
            data BYTEA,
            expiry TIMESTAMP WITHOUT TIME ZONE
        );

        --- Unique session_id
        CREATE UNIQUE INDEX IF NOT EXISTS
            uq_{table_name}_session_id ON {table_name} (session_id);

        --- Index for expiry timestamp
        CREATE INDEX IF NOT EXISTS
            {table_name}_expiry_idx ON {table_name} (expiry);
        """
            )

    def _unsign_sid(self, app: Flask, sid: str) -> str:
        signer = self._get_signer(app)
        if not self.use_signer or not signer:
            raise RuntimeError("Session signing is disabled.")

        return signer.unsign(sid).decode()

    def _delete_expired_sessions(self) -> None:
        """Delete all expired sessions from the database."""
        with self._get_cursor() as cur:
            cur.execute(
                f"DELETE FROM {self.table_name} WHERE expiry < NOW();",
            )

    @retry_query(max_attempts=3)
    def _delete_session(self, sid: str) -> None:
        with self._get_cursor() as cur:
            cur.execute(
                "DELETE FROM {table} WHERE session_id = %(session_id)s".format(
                    table=self.table_name
                ),
                dict(session_id=self._get_store_id(sid)),
            )

    @retry_query(max_attempts=3)
    def _retrieve_session_data(self, sid: str) -> bytes | None:
        with self._get_cursor() as cur:
            cur.execute(
                """
                --- If the current sessions is expired, delete it
                DELETE FROM {table} WHERE session_id = %(session_id)s AND expiry < NOW();
                --- Else retrieve it
                SELECT data FROM {table} WHERE session_id = %(session_id)s;""".format(
                    table=self.table_name
                ),
                dict(session_id=self._get_store_id(sid)),
            )
            data = cur.fetchone()

            return data[0] if data is not None else None

    @retry_query()
    def _upsert_session(self, sid: str, data: bytes, expires: datetime) -> None:
        with self._get_cursor() as cur:
            cur.execute(
                """INSERT INTO {table} (session_id, data, expiry)
                    VALUES (%(session_id)s, %(data)s, %(expiry)s)
                    ON CONFLICT (session_id)
                    DO UPDATE SET data = %(data)s, expiry = %(expiry)s;
                """.format(
                    table=self.table_name
                ),
                dict(session_id=self._get_store_id(sid), data=data, expiry=expires),
            )

    def open_session(self, app: Flask, request: Request) -> ServerSideSession:
        if self.autodelete_expired_sessions and random.randint(0, 1000) == 0:
            app.logger.info("Deleting expired sessions")
            try:
                self._delete_expired_sessions()
            except Exception as e:
                app.logger.exception(
                    e, "Failed to delete expired sessions. Skipping..."
                )

        sid = request.cookies.get(app.session_cookie_name)

        if not sid:
            sid = self._generate_sid()
            return self.session_class(sid=sid, permanent=self.permanent)

        assert sid
        if self.use_signer:
            try:
                sid = self._unsign_sid(app, sid)
            except BadSignature:
                sid = self._generate_sid()
                return self.session_class(sid=sid, permanent=self.permanent)

        saved_session_data = self._retrieve_session_data(sid)

        if saved_session_data is not None:
            try:
                data = self.serializer.loads(want_bytes(saved_session_data))
                return self.session_class(data, sid=sid)
            except Exception:
                return self.session_class(sid=sid, permanent=self.permanent)
        return self.session_class(sid=sid, permanent=self.permanent)

    def save_session(
        self, app: Flask, session: ServerSideSession, response: Response
    ) -> None:
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)

        if not session:
            if session.modified:
                self._delete_session(session.sid)

                response.delete_cookie(
                    app.session_cookie_name, domain=domain, path=path
                )
            return

        if not self.should_set_cookie(app, session):
            return

        conditional_cookie_kwargs = {}
        httponly = self.get_cookie_httponly(app)
        secure = self.get_cookie_secure(app)

        if self.has_same_site_capability:
            conditional_cookie_kwargs["samesite"] = self.get_cookie_samesite(app)

        expires = self.get_expiration_time(app, session)
        val = self.serializer.dumps(dict(session))

        self._upsert_session(session.sid, val, expires)

        if self.use_signer:
            session_id = self._get_signer(app).sign(want_bytes(session.sid))
        else:
            session_id = session.sid

        response.set_cookie(
            app.session_cookie_name,
            session_id,
            expires=expires,
            httponly=httponly,
            domain=domain,
            path=path,
            secure=secure,
            **conditional_cookie_kwargs,
        )
