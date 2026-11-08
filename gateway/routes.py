"""Routes: which upstream API paths the gateway forwards in brokered mode.

docs/threat-model.md §3 (model traffic): "dedicated authenticated route, fixed account and
operation scope; arbitrary runner processes cannot use a generic relay". Without this, any
process in the runner could use the gateway, and the real key it adds, to call any API
endpoint (upload files, manage batches, ...). Only the endpoints the agent needs are allowed.

Pass-through mode (gateway run directly on your machine, no session token) is not restricted:
the agent there uses its own credentials, and a subscription login needs other endpoints.
"""
from . import config


def allowed(path):
    """True if this request path (query string ignored) may be forwarded upstream."""
    return path.split("?", 1)[0] in config.ALLOWED_PATHS
