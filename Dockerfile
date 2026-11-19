# ssh-honeypot container image.
# Runs as an unprivileged user without capabilities; listens on 2222 (unprivileged).

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install . && rm -rf /root/.cache /app/src

COPY config.yml ./config.yml

RUN useradd --system --uid 10001 --gid nogroup --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin honeypot \
    && mkdir -p /data \
    && chown honeypot:nogroup /data

USER 10001

# Inside the container the honeypot must listen on all interfaces; what is
# reachable from outside is decided by the published ports in docker-compose.yml.
ENV HONEYPOT_CONFIG=/app/config.yml \
    HONEYPOT_DB=/data/honeypot.db \
    HONEYPOT_STATE_DIR=/data \
    HONEYPOT_AUTH_LOG=/data/auth.log \
    HONEYPOT_LISTEN_HOST=0.0.0.0 \
    HONEYPOT_LISTEN_PORT=2222

EXPOSE 2222

# No HEALTHCHECK on purpose: a probe that connects to the SSH port would be
# recorded as an attacker session every 30 seconds.

ENTRYPOINT ["honeypot"]
CMD ["run"]
