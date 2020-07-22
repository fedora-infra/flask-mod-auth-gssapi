import pytest
from flask import Flask

from flask_mod_auth_gssapi import FlaskModAuthGSSAPI


@pytest.fixture
def app():
    app = Flask("test")
    FlaskModAuthGSSAPI(app)
    app.config["TESTING"] = True
    return app


@pytest.fixture
def wsgi_env():
    return {"KRB5CCNAME": "/tmp/ignore", "GSS_NAME": "dummy@EXAMPLE.TEST"}
