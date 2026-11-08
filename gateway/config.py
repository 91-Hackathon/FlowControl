"""Gateway settings. Override with environment variables."""
import ipaddress
import os

# Where the gateway listens. The agent is pointed here via ANTHROPIC_BASE_URL.
# Default: this machine only. Inside the gateway container it's 0.0.0.0, so the runner
# container can reach it over the internal Docker network.
HOST = os.environ.get("FC_HOST", "127.0.0.1")
PORT = int(os.environ.get("FC_PORT", "8787"))

# The real LLM API the gateway forwards to.
UPSTREAM_HOST = os.environ.get("FC_UPSTREAM", "api.anthropic.com")
# "http" only for a local fake API (tests, offline rehearsal). Real use is always https.
UPSTREAM_SCHEME = os.environ.get("FC_UPSTREAM_SCHEME", "https")

# Credentials (gateway/credentials.py). Both come from the environment, never from a file.
# SESSION_TOKEN: what the agent's container holds instead of a real key. Set = brokered mode.
# UPSTREAM_API_KEY: the real key, known only to the gateway.
SESSION_TOKEN = os.environ.get("FC_SESSION_TOKEN", "")
UPSTREAM_API_KEY = os.environ.get("FC_UPSTREAM_API_KEY", "")

# Upstream paths forwarded in brokered mode (gateway/routes.py): the model endpoints only.
ALLOWED_PATHS = {p.strip() for p in os.environ.get(
    "FC_ALLOWED_PATHS", "/v1/messages,/v1/messages/count_tokens").split(",") if p.strip()}

# Forward proxy for the runner's other egress (gateway/proxy.py). The runner points HTTP_PROXY /
# HTTPS_PROXY here; the gateway allows or denies each destination by policy and session state.
PROXY_PORT = int(os.environ.get("FC_PROXY_PORT", "8888"))

# Live feed for the dashboard: ws://HOST:LIVE_PORT/events (debug page at http://HOST:LIVE_PORT/).
LIVE_PORT = int(os.environ.get("FC_LIVE_PORT", "8080"))
# Networks that may NOT use the live feed. The feed also accepts commands (approve, stop), so
# the agent's own network must never reach it (threat model category 7). Comma-separated CIDRs.
LIVE_DENY_NETS = [ipaddress.ip_network(n.strip()) for n in os.environ.get(
    "FC_LIVE_DENY_NETS", "").split(",") if n.strip()]

# The policy tool calls are judged against (gateway/policy.py). Outside the runner: compose
# mounts it into the gateway container only, read-only. Missing or broken = everything blocked.
POLICY_FILE = os.environ.get("FC_POLICY_FILE", "policy/default.toml")

# Where structured events (protocol/EVENTS.md) are written, one JSON object per line.
EVENTS_FILE = os.environ.get("FC_EVENTS_FILE", "logs/events.jsonl")

# Seconds to wait for the upstream API (long, because agent responses stream for a while).
UPSTREAM_TIMEOUT = 600

# How long an "ask" tool call waits for a human on the dashboard before it is denied (fail closed).
APPROVAL_TIMEOUT = int(os.environ.get("FC_APPROVAL_TIMEOUT", "120"))

# Budget and lifetime (threat model categories 6, 5). The gateway revokes the run when either is
# exceeded: a cap on model requests, and a wall-clock lifetime for the session token. 0 = no limit.
MAX_MODEL_REQUESTS = int(os.environ.get("FC_MAX_MODEL_REQUESTS", "400"))
SESSION_TTL = int(os.environ.get("FC_SESSION_TTL", "3600"))  # seconds; the per-run token expires after this

# Canary markers (comma-separated) to watch for in request bodies. A canary reaching the model is
# informational (secrets naturally enter the prompt); a canary reaching any other destination is a
# red flag. The policy file's [canaries] list is used when set; this is the env fallback.
CANARIES = [c.strip() for c in os.environ.get("FC_CANARIES", "").split(",") if c.strip()]
