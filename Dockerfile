# Epyon Web UI — FastAPI backend + static SPA
#
# This image serves the dashboard/API only. Security scan layers still run as
# their own containers via the host's Docker/Podman engine, so the Docker CLI
# is installed here and the host's container socket must be bind-mounted at
# runtime (see docker-compose.yml). Git is required for scan scripts that
# clone target repositories.
FROM python:3.12-slim

ARG DOCKER_CLI_VERSION=27.3.1

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        curl \
        ca-certificates \
    && curl -fsSL "https://download.docker.com/linux/static/stable/$(uname -m)/docker-${DOCKER_CLI_VERSION}.tgz" \
        -o /tmp/docker-cli.tgz \
    && tar -xzf /tmp/docker-cli.tgz -C /tmp \
    && mv /tmp/docker/docker /usr/local/bin/docker \
    && rm -rf /tmp/docker-cli.tgz /tmp/docker \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first for better layer caching
COPY web/api/requirements.txt /app/web/api/requirements.txt
RUN python3 -m pip install --no-cache-dir -r /app/web/api/requirements.txt

# Copy the full repository so scan scripts, configuration, and VERSION are
# available to the API at runtime (see EPYON_ROOT resolution in main.py).
COPY . /app

# Immutable, build-time copy of the shipped STIG source files. docker-compose.yml
# bind-mounts ./configuration over /app/configuration to persist STIG scan state
# and any user-added STIG files across image rebuilds — but that also means an
# empty/missing host-side configuration/stigs directory silently breaks Layer 13
# (STIG Compliance Assessment). This backup lives outside /app so the bind mount
# can never shadow it; run-stig-scan.sh self-heals from it if configuration/stigs
# is empty or missing at scan time. See CHANGELOG for details.
RUN mkdir -p /opt/epyon-defaults && cp -r /app/configuration /opt/epyon-defaults/configuration

ENV HOST=0.0.0.0 \
    PORT=8057 \
    PYTHONUNBUFFERED=1

EXPOSE 8057

WORKDIR /app/web

CMD ["sh", "-c", "python3 -m uvicorn api.main:app --host ${HOST} --port ${PORT} --app-dir /app/web"]
