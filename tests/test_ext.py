from types import SimpleNamespace

import pytest
from flask import Flask, g
from werkzeug.exceptions import Forbidden, InternalServerError, Unauthorized

from flask_mod_auth_gssapi import FlaskModAuthGSSAPI


def test_delayed_init(mocker):
    init_app = mocker.patch.object(FlaskModAuthGSSAPI, "init_app")
    FlaskModAuthGSSAPI(None)
    init_app.assert_not_called()


def test_multithread(app):
    with app.test_request_context("/", multithread=True):
        with pytest.raises(InternalServerError):
            app.preprocess_request()


def test_no_krb5ccname(app, wsgi_env):
    del wsgi_env["KRB5CCNAME"]
    with app.test_request_context("/", environ_base=wsgi_env):
        app.preprocess_request()
        assert g.principal is None
        assert g.username is None


def test_no_gss_name(app, wsgi_env):
    del wsgi_env["GSS_NAME"]
    with app.test_request_context("/", environ_base=wsgi_env):
        app.preprocess_request()
        assert g.principal is None
        assert g.username is None


def test_no_cache(app, wsgi_env):
    with app.test_request_context("/", environ_base=wsgi_env):
        with pytest.raises(Forbidden):
            app.preprocess_request()
            assert g.principal is None
            assert g.username is None


def test_expired(app, wsgi_env, mocker):
    creds_factory = mocker.patch("gssapi.Credentials")
    creds_factory.return_value = SimpleNamespace(lifetime=0)
    with app.test_request_context("/", environ_base=wsgi_env):
        with pytest.raises(Unauthorized) as excinfo:
            app.preprocess_request()
            assert g.principal is None
            assert g.username is None
    assert excinfo.value.description == "Credential lifetime has expired"


def test_nominal(app, wsgi_env, mocker):
    creds_factory = mocker.patch("gssapi.Credentials")
    creds_factory.return_value = SimpleNamespace(lifetime=10)
    with app.test_request_context("/", environ_base=wsgi_env):
        app.preprocess_request()
        assert g.principal == "dummy@EXAMPLE.TEST"
        assert g.username == "dummy"


def test_alt_abort(app, wsgi_env, mocker):
    """Allow passing an alternate abort() function."""
    mock_abort = mocker.Mock()
    mock_abort.side_effect = RuntimeError
    app = Flask("test")
    app.config["TESTING"] = True
    FlaskModAuthGSSAPI(app, abort=mock_abort)
    with app.test_request_context("/", environ_base=wsgi_env):
        with pytest.raises(RuntimeError):
            app.preprocess_request()
            assert g.principal is None
            assert g.username is None
    mock_abort.assert_called_once()
    call_args = mock_abort.call_args_list[0][0]
    assert call_args[0] == 403
    assert call_args[1].startswith("Invalid credentials ")
