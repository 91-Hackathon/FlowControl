"""Credentials: the real API key lives here, never in the agent's environment.

docs/threat-model.md, categories 2 and 5. The runner only holds a per-session token.
On every request the gateway:
  1. checks the token the agent presented (x-api-key or Authorization: Bearer)
  2. removes it
  3. adds the real key, which only the gateway knows
If any check fails, the request is refused here and never reaches the API (fail closed).

Two modes, decided by settings:
  - Brokered (FC_SESSION_TOKEN set): the container setup. The token must match, and a real
    key (FC_UPSTREAM_API_KEY) must be configured, or nothing goes out.
  - Pass-through (FC_SESSION_TOKEN not set): running the gateway directly on your machine
    (M1 style). Whatever credential the agent sends is forwarded unchanged.
"""
import hmac
from dataclasses import dataclass, field

from . import config

AUTH_HEADERS = {"x-api-key", "authorization"}


@dataclass
class AuthResult:
    ok: bool
    headers: dict = field(default_factory=dict)  # headers to send upstream (when ok)
    status: int = 200                            # HTTP status to return (when not ok)
    error_type: str = ""
    message: str = ""


def presented_token(headers):
    """The credential the agent sent, from x-api-key or Authorization: Bearer (any header case)."""
    lower = {k.lower(): v for k, v in headers.items()}
    key = lower.get("x-api-key")
    if key:
        return key.strip()
    auth = lower.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


def check(headers):
    """Decide whether this request may go upstream, and with which credentials."""
    if not config.SESSION_TOKEN:
        return AuthResult(ok=True, headers=dict(headers.items()))  # pass-through mode

    # Refusals use 403: Claude Code retries 401 and 5xx (tested: 6 retries in 30s, no message
    # shown), but stops on 403 and prints our message. Refused either way; this only changes
    # how the agent reacts.
    token = presented_token(headers)
    if not token or not hmac.compare_digest(token.encode(), config.SESSION_TOKEN.encode()):
        return AuthResult(False, status=403, error_type="permission_error",
                          message="FlowControl gateway: unknown session token")
    if not config.UPSTREAM_API_KEY:
        return AuthResult(False, status=403, error_type="permission_error",
                          message="FlowControl gateway: no upstream API key configured")

    out = {k: v for k, v in headers.items() if k.lower() not in AUTH_HEADERS}
    out["x-api-key"] = config.UPSTREAM_API_KEY
    return AuthResult(ok=True, headers=out)


def mode():
    return "brokered" if config.SESSION_TOKEN else "pass-through"
