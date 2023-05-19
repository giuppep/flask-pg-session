CREATE_TABLE = """CREATE TABLE IF NOT EXISTS {table} (
    session_id VARCHAR(255) NOT NULL PRIMARY KEY,
    created TIMESTAMP WITHOUT TIME ZONE DEFAULT (NOW() AT TIME ZONE 'utc'),
    data BYTEA,
    expiry TIMESTAMP WITHOUT TIME ZONE
);

--- Unique session_id
CREATE UNIQUE INDEX IF NOT EXISTS
    uq_{table}_session_id ON {table} (session_id);

--- Index for expiry timestamp
CREATE INDEX IF NOT EXISTS
    {table}_expiry_idx ON {table} (expiry);
"""

RETRIEVE_SESSION_DATA = """--- If the current sessions is expired, delete it
DELETE FROM {table} WHERE session_id = %(session_id)s AND expiry < NOW();
--- Else retrieve it
SELECT data FROM {table} WHERE session_id = %(session_id)s;
"""


UPSERT_SESSION = """INSERT INTO {table} (session_id, data, expiry)
    VALUES (%(session_id)s, %(data)s, %(expiry)s)
    ON CONFLICT (session_id)
    DO UPDATE SET data = %(data)s, expiry = %(expiry)s;
"""


DELETE_EXPIRED_SESSIONS = "DELETE FROM {table} WHERE expiry < NOW();"
DELETE_SESSION = "DELETE FROM {table} WHERE session_id = %(session_id)s"
