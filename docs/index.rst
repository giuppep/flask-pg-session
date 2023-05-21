Welcome to flask-pg-session's documentation!
============================================

.. automodule:: flask_pg_session
   :noindex:

.. contents:: Table of contents
    :local:
    :backlinks: entry
    :depth: 2

Installation
************

You can install the ``FlaskPgSession`` extension with ``pip``:

.. code-block:: bash

   pip install flask-pg-session


Usage
*****


Usage is pretty straightforward: just import ``FlaskPgSession`` and intialise it with
your ``Flask`` app:

.. code-block:: python

   from flask import Flask
   from flask_pg_session import FlaskPgSession

   app = Flask("my-app")

   # You can either pass the app as an argument to the constructor
   FlaskPgSession(app)

   # or initialise it separately
   session = FlaskPgSession()
   session.init_app(app)


API & Configuration
*******************


.. module:: flask_pg_session.session

.. autoclass:: FlaskPgSession
    :members:



License
*******

``FlaskPgSession`` is open source and released under the MIT License.