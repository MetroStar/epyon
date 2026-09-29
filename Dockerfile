# Epyon Web UI — FastAPI backend + static SPA
#
# This image serves the dashboard/API only. Security scan layers still run as
# their own containers via the host's Docker/Podman engine, so the Docker CLI
# is installed here and the host's container socket must be bind-mounted at
# runtime (see docker-compose.yml). Git is required for scan scripts that
# clone target repositories. The Helm CLI is installed directly (Layer 5 —
# Helm Chart Build — shells out to `helm` itself rather than running it in
# its own container, unlike most other scan layers). `jq` is required by
# nearly every scan script's own result-summary/count logic (SBOM, Checkov,
# Trivy, Grype, Anchore, etc. all pipe their JSON output through `jq` to
# report a finding/artifact count); those call sites follow a
# `jq ... || echo "0"` fallback pattern that was written assuming `jq`
# exists, so without it installed here every one of those tools *appears* to
# find zero results even when its underlying scan produced real findings.
FROM python:3.12-slim

ARG DOCKER_CLI_VERSION=27.3.1
ARG HELM_VERSION=3.16.4

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        curl \
        ca-certificates \
        jq \
    && curl -fsSL "https://download.docker.com/linux/static/stable/$(uname -m)/docker-${DOCKER_CLI_VERSION}.tgz" \
        -o /tmp/docker-cli.tgz \
    && tar -xzf /tmp/docker-cli.tgz -C /tmp \
    && mv /tmp/docker/docker /usr/local/bin/docker \
    && rm -rf /tmp/docker-cli.tgz /tmp/docker \
    && HELM_ARCH="$(uname -m)" \
    && case "$HELM_ARCH" in x86_64) HELM_ARCH=amd64 ;; aarch64) HELM_ARCH=arm64 ;; esac \
    && curl -fsSL "https://get.helm.sh/helm-v${HELM_VERSION}-linux-${HELM_ARCH}.tar.gz" \
        -o /tmp/helm.tgz \
    && tar -xzf /tmp/helm.tgz -C /tmp \
    && mv "/tmp/linux-${HELM_ARCH}/helm" /usr/local/bin/helm \
    && rm -rf /tmp/helm.tgz "/tmp/linux-${HELM_ARCH}" \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first for better layer caching
COPY web/api/requirements.txt /app/web/api/requirements.txt
RUN python3 -m pip install --no-cache-dir -r /app/web/api/requirements.txt

# pip-audit is shelled out to directly by scripts/shell/run-pip-audit-scan.sh
# (Layer 8.5 — Direct Dependency Scanning), unlike the other scan layers
# which run as their own Docker containers. Without it installed in this
# image, any scan or self-assessment run triggered from the web UI silently
# reports zero findings for Layer 8.5 (the script exits early with
# "pip-audit is not installed", and the caller treats that as a soft
# failure) instead of a clear error.
RUN python3 -m pip install --no-cache-dir pip-audit

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
