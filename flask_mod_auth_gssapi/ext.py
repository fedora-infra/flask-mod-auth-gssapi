import os

import gssapi
from flask import abort, current_app, g, request
from werkzeug.exceptions import Unauthorized


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
            current_app.logger.warning(
                "Delegated credentials not found: %r", ccache_location
            )
            self._authenticate()

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
            current_app.logger.info("Credential lifetime has expired.")
            if ccache_type == "FILE":
                try:
                    os.remove(ccache_location)
                except OSError as e:
                    current_app.logger.warning(
                        "Could not remove expired credential at %s: %s",
                        ccache_location,
                        e,
                    )
            self._authenticate()

        g.gss_name = gss_name
        g.gss_creds = creds
        g.principal = gss_name.display_as(gssapi.NameType.kerberos_principal)
        g.username = g.principal.split("@")[0]

    def _authenticate(self):
        """Unset mod_auth_gssapi's session cookie and restart GSSAPI authentication"""
        current_app.logger.debug(
            "Clearing the session and asking for re-authentication."
        )
        exc = Unauthorized("Re-authentication is necessary.")
        exc.response = exc.get_response()
        exc.response.headers["WWW-Authenticate"] = "Negotiate"
        session_header = current_app.config["MOD_AUTH_GSSAPI_SESSION_HEADER"]
        exc.response.headers[session_header] = "MagBearerToken="
        raise exc
