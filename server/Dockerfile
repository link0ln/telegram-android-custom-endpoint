FROM python:3.12-slim

WORKDIR /app
# stdlib only — no pip dependencies, no requirements.txt
COPY *.py ./
COPY tests ./tests

# Subscriptions live in /data (a named volume: recreating the container without
# one silently destroys every subscription) and the pidfile in /run, which
# relayctl signals so a revocation takes effect in about a second.
VOLUME ["/data"]
ENV RELAY_DB=/data/relay.db \
    RELAY_PIDFILE=/run/mtrelay.pid

ENTRYPOINT ["python3", "mtrelay.py"]
