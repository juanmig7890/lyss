# LYSS web interface and collector, for Linux hosts.
# Data (inventory, encrypted credentials, results, history) lives in the /data volume.
# Secrets are AES-256-GCM encrypted with /data/master.key (or LYSS_MASTER_KEY): back it up.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LYSS_HOME=/app \
    LYSS_DATA_DIR=/data \
    LYSS_ALLOW_REMOTE=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY spec ./spec
COPY adapters ./adapters
COPY data ./data

RUN pip install --no-cache-dir . \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin lyss \
 && mkdir -p /data && chown lyss:lyss /data

USER lyss
VOLUME ["/data"]
EXPOSE 8765

HEALTHCHECK --interval=60s --timeout=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/login', timeout=4)" || exit 1

# Listens on all interfaces INSIDE the container only: publish the port on 127.0.0.1 (see
# docker-compose.yml) or behind an HTTPS reverse proxy. The UI itself speaks plain HTTP.
CMD ["lyss", "ui", "--host", "0.0.0.0", "--port", "8765"]
