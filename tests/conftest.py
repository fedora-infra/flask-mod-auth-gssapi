from types import SimpleNamespace

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
    return {"KRB5CCNAME": "/tmp/ignore", "GSS_NAME": "dummy@EXAMPLE.TEST"}  # noqa: S108


@pytest.fixture
def credential(mocker):
    creds_factory = mocker.patch("gssapi.Credentials")
    cred = creds_factory.return_value = SimpleNamespace(lifetime=10)
    return cred


@pytest.fixture
def expired_credential(credential):
    credential.lifetime = 0
    return credential
