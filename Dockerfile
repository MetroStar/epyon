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
FROM golang:1.27.3-alpine AS cli-builder

ENV CGO_ENABLED=0 GOFLAGS=-mod=mod GOMAXPROCS=2
RUN apk add --no-cache git

ARG BUILDX_VERSION=0.38.2
ARG HELM_VERSION=3.22.1
WORKDIR /src/buildx
# Buildx uses the obsolete daemon module only for this frozen naming utility.
# Keep that utility and its license, not the unrelated daemon dependency.
RUN git clone --depth=1 --branch "v${BUILDX_VERSION}" https://github.com/docker/buildx.git . \
    && mkdir -p internal/namesgenerator \
    && cp vendor/github.com/docker/docker/pkg/namesgenerator/names-generator.go internal/namesgenerator/ \
    && cp vendor/github.com/docker/docker/LICENSE internal/namesgenerator/LICENSE \
    && sed -i 's|github.com/docker/docker/pkg/namesgenerator|github.com/docker/buildx/internal/namesgenerator|' store/util.go \
    && go mod edit -droprequire=github.com/docker/docker \
    && go get golang.org/x/net@v0.62.0 github.com/moby/go-archive@v0.3.0 \
    && go mod tidy \
    && go list -m all > /tmp/buildx-modules \
    && ! grep -q '^github.com/docker/docker ' /tmp/buildx-modules \
    && go test -p 2 ./store ./internal/namesgenerator \
    && go build -p 2 -trimpath -ldflags "-s -w -X github.com/docker/buildx/version.Version=v${BUILDX_VERSION}-epyon" \
        -o /out/docker-buildx ./cmd/buildx

WORKDIR /src/helm
RUN git clone --depth=1 --branch "v${HELM_VERSION}" https://github.com/helm/helm.git . \
    && go get golang.org/x/net@v0.62.0 \
    && go build -p 2 -trimpath -ldflags "-s -w -X helm.sh/helm/v3/internal/version.version=v${HELM_VERSION}-epyon" \
        -o /out/helm ./cmd/helm

FROM cgr.dev/chainguard/wolfi-base:latest

ARG NPM_VERSION=12.2.2

RUN apk upgrade --no-cache \
    && apk add --no-cache bash coreutils findutils grep sed gnutar gzip unzip \
        git curl ca-certificates jq python-3.12 py3.12-pip nodejs-24 docker-cli \
    && mkdir -p /usr/local/lib/node_modules/npm /usr/local/bin \
    && curl -fsSL "https://registry.npmjs.org/npm/-/npm-${NPM_VERSION}.tgz" -o /tmp/npm.tgz \
    && tar -xzf /tmp/npm.tgz --strip-components=1 -C /usr/local/lib/node_modules/npm \
    && rm /tmp/npm.tgz \
    && ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
    && node --version && npm --version && npx --version \
    && python3 -m venv --system-site-packages --without-pip /opt/venv

ENV PATH="/opt/venv/bin:${PATH}"
COPY --from=cli-builder /out/helm /usr/local/bin/helm
COPY --from=cli-builder /out/docker-buildx /usr/local/lib/docker/cli-plugins/docker-buildx
COPY --from=cli-builder /src/buildx/internal/namesgenerator/LICENSE /usr/share/licenses/buildx-namesgenerator/LICENSE
RUN docker --version && docker buildx version && helm version --short

WORKDIR /app

# Install Python dependencies first for better layer caching
COPY web/api/requirements.txt /app/web/api/requirements.txt
# Resolve the native scanners together with the API so their dependency pins
# cannot silently leave the web environment inconsistent.
RUN python3 -m pip install --no-cache-dir -r /app/web/api/requirements.txt pip-audit semgrep awscli \
    && python3 -m pip check

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

CMD ["sh", "-c", "bash /app/scripts/shell/ecr-refresh-loop.sh & exec python3 -m uvicorn api.main:app --host ${HOST} --port ${PORT} --app-dir /app/web"]
