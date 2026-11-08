# FlowControl gateway container. Build from the project root:
#   docker build -f gateway/Dockerfile -t flowcontrol-gateway .
# Normally started by compose.yaml, which puts it on both the agent's internal network
# and an outside network: it is the runner's only way out.

FROM python:3.12-slim

# Standard library only: nothing to pip install.
WORKDIR /app
COPY gateway/ gateway/

# Unprivileged user; logs/ is where events.jsonl goes (mounted from the host by compose,
# outside anything the runner can write: threat model category 7).
RUN useradd --uid 10001 --create-home fc && mkdir -p logs && chown fc:fc logs
USER fc

ENV FC_HOST=0.0.0.0 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8787 8080 8888
CMD ["python3", "-m", "gateway"]
