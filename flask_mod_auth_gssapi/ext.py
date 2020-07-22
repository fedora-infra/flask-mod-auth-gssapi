import os

import gssapi
from flask import abort, g, request


class FlaskModAuthGSSAPI:
    def __init__(self, app, abort=abort):
        self.abort = abort
        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        app.before_request(self._gssapi_check)

    def _gssapi_check(self):
        g.gss_name = g.gss_creds = g.principal = g.username = None

        wsgi_env = request.environ
        if wsgi_env["wsgi.multithread"]:
            self.abort(
                500, "GSSAPI is not compatible with multi-threaded WSGI servers.",
            )

        ccache = wsgi_env.get("KRB5CCNAME")
        if not ccache:
            return  # Maybe the endpoint is not protected, stop here

        # The C libraries will look for the cache in the process' environment variables
        os.environ["KRB5CCNAME"] = ccache

        principal = wsgi_env.get("GSS_NAME")
        if not principal:
            return  # Maybe the endpoint is not protected, stop here

        gss_name = gssapi.Name(principal, gssapi.NameType.kerberos_principal)
        try:
            creds = gssapi.Credentials(
                usage="initiate", name=gss_name, store={"ccache": ccache}
            )
        except gssapi.exceptions.GSSError as e:
            self.abort(
                403, f"Invalid credentials ({e})",
            )
        if creds.lifetime <= 0:
            self.abort(401, "Credential lifetime has expired")

        g.gss_name = gss_name
        g.gss_creds = creds
        g.principal = gss_name.display_as(gssapi.NameType.kerberos_principal)
        g.username = g.principal.split("@")[0]
