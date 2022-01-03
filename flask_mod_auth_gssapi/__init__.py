from .ext import FlaskModAuthGSSAPI  # noqa: F401


# Set the version
try:
    import importlib.metadata

    __version__ = importlib.metadata.version("flask_mod_auth_gssapi")
except ImportError:
    try:
        import pkg_resources

        try:
            __version__ = pkg_resources.get_distribution(
                "flask_mod_auth_gssapi"
            ).version
        except pkg_resources.DistributionNotFound:
            __version__ = None
    except ImportError:
        __version__ = None
