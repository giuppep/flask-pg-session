# FlaskPgSession

`FlaskPgSession` is a [`Flask`](https://flask.palletsprojects.com/) extensions that
implements server-side session support and stores the data in a PostgreSQL table.

It is inspired by [`Flask-Session`](https://flasksession.readthedocs.io/en/latest/)
but it's focused only on integration with PostgreSQL and therefore has fewer
dependencies.

It is intended for people that are already using Flask with PostgreSQL and do not want
to add another dependency to their app just for storing sessions (e.g. Redis).

## Installation

You can install `FlaskPgSession` using `pip`

```bash
pip install flask-pg-session
```

## Usage

Usage is pretty straightforward: just import `FlaskPgSession` and intialise it with
your `Flask` app:

```python
from flask import Flask
from flask_pg_session import FlaskPgSession

app = Flask("my-app")

# You can either pass the app as an argument to the constructor
FlaskPgSession(app)

# or initialise it separately
session = FlaskPgSession()
session.init_app(app)
```

## Configuration

The extension can be configured via the `Flask` config file. The following options are
available:

- `SQLALCHEMY_DATABASE_URI`: The URI of the PostgreSQL database to use.
- `SESSION_PG_TABLE`: The name of the table to store sessions in. Defaults to `flask_sessions`.
- `SESSION_PG_SCHEMA`: The name of the schema to store sessions in. Defaults to `public`.
- `SESSION_KEY_PREFIX`: The prefix to use for session IDs. Absent by default.
- `SESSION_USE_SIGNER`: Whether to sign session IDs. Defaults to False.
- `SESSION_PERMANENT`: Whether to set the `permanent` flag on sessions. Defaults to True.
- `SESSION_AUTODELETE_EXPIRED`: Whether to automatically delete expired
sessions. Defaults to True.
- `SESSION_PG_MAX_DB_CONN`: The maximum number of database connections to use. Defaults to 10.

## Contributions

Contributions are welcome! If you encounter any issues, have suggestions, or would like
to contribute to `FlaskPgSession`, please feel free to submit a pull request or
open an issue.


## License

`FlaskPgSession` is open source and released under the MIT License.