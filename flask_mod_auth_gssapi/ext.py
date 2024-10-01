import logging
import os

import gssapi
from flask import abort, current_app, g, redirect, request

_log = logging.getLogger(__name__)


class FlaskModAuthGSSAPI:
    def __init__(self, app=None, abort=abort):
        self.abort = abort
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        app.before_request(self._gssapi_check)
        app.config.setdefault("MOD_AUTH_GSSAPI_SESSION_HEADER", "X-Replace-Session")

    def _gssapi_check(self):
        g.gss_name = g.gss_creds = g.principal = g.username = None

        wsgi_env = request.environ
        if wsgi_env["wsgi.multithread"]:
            self.abort(
                500,
                "GSSAPI is not compatible with multi-threaded WSGI servers.",
            )

        ccache = wsgi_env.get("KRB5CCNAME")
        if not ccache:
            return  # Maybe the endpoint is not protected, stop here

        # The C libraries will look for the cache in the process' environment variables
        os.environ["KRB5CCNAME"] = ccache

        principal = wsgi_env.get("GSS_NAME")
        if not principal:
            return  # Maybe the endpoint is not protected, stop here

        ccache_type, _sep, ccache_location = ccache.partition(":")
        if ccache_type == "FILE" and not os.path.exists(ccache_location):
            _log.warning("Delegated credentials not found: %r", ccache_location)
            return self._clear_session()

        gss_name = gssapi.Name(principal, gssapi.NameType.kerberos_principal)
        try:
            creds = gssapi.Credentials(
                usage="initiate", name=gss_name, store={"ccache": ccache}
            )
        except gssapi.exceptions.GSSError as e:
            self.abort(
                403,
                f"Invalid credentials ({e})",
            )
        try:
            lifetime = creds.lifetime
        except gssapi.exceptions.ExpiredCredentialsError:
            lifetime = 0
        if lifetime <= 0:
            _log.info("Credential lifetime has expired.")
            return self._clear_session()

        g.gss_name = gss_name
        g.gss_creds = creds
        g.principal = gss_name.display_as(gssapi.NameType.kerberos_principal)
        g.username = g.principal.split("@")[0]

    def _clear_session(self):
        """Unset mod_auth_gssapi's session cookie and redirect to the same URL"""
        if request.method in ("POST", "PUT", "DELETE"):
            self.abort(
                401, "Re-authentication is necessary, please try your request again."
            )
        response = redirect(request.url)
        response.headers[current_app.config["MOD_AUTH_GSSAPI_SESSION_HEADER"]] = (
            "MagBearerToken="
        )
        return response
