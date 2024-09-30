# Flask Mod Auth GSSAPI


A Flask extention to make use of the authentication provided by the
[mod_auth_gssapi](https://github.com/gssapi/mod_auth_gssapi) extention of
Apache's HTTPd. See [FASJSON](https://github.com/fedora-infra/fasjson) for a
usage example.

If you're using sessions from `mod_session` with `mod_auth_gssapi`, set your
application's `MOD_AUTH_GSSAPI_SESSION_HEADER` configuration variable to the
value you used in Apache's configuration file for `SessionHeader`. This will
signal `mod_session` to invalidate the session when the authentication
credential has expired.
