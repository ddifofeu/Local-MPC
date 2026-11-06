# syntax=docker/dockerfile:1
#
# Hardened image for the orchestrator (stdio MCP server — no listening port).
# The base image is pinned by digest, so security updates arrive only when this line changes.
# To update it:
#   docker buildx imagetools inspect python:3.11-slim-bookworm --format '{{json .Manifest.Digest}}'
ARG PYTHON_IMAGE=python:3.11-slim-bookworm@sha256:a83ba18aef0f865b1a4a611c2cf460fe446f2795673bbb9fe43be570439e3b39

# ---------- build stage: resolve wheels with hash verification -------------
FROM ${PYTHON_IMAGE} AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY requirements.txt /tmp/requirements.txt
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-hashes --no-deps -r /tmp/requirements.txt

# ---------- runtime stage: no compiler, no curl, no git, no root -----------
FROM ${PYTHON_IMAGE}
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN groupadd --system --gid 10001 orch \
 && useradd --system --uid 10001 --gid orch --no-create-home --shell /usr/sbin/nologin orch \
 && install -d -o orch -g orch -m 0700 /var/log/claude-orchestrator \
 && install -d -o orch -g orch -m 0700 /work
COPY --from=build /opt/venv /opt/venv
# 0555, not 0444: --chmod also applies to the directory, which needs +x to be traversed.
COPY --chown=root:root --chmod=0555 orchestrator /app/orchestrator
USER 10001:10001
WORKDIR /app
# stdio transport: there is no HTTP endpoint to probe.
HEALTHCHECK NONE
ENTRYPOINT ["python", "-m", "orchestrator", "--config", "/etc/orchestrator/config.json"]
