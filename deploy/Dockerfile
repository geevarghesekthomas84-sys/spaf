# ─────────────────────────────────────────────────────────────────────────────
# SPAF API — hardened container image for `spaf serve`
# Build from the repo root:  docker build -f deploy/Dockerfile -t spaf-api .
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS build

WORKDIR /src
COPY pyproject.toml README.md ./
COPY spaf ./spaf
# Build a wheel so the runtime image carries no build context or caches.
RUN pip install --no-cache-dir build && python -m build --wheel --outdir /dist

FROM python:3.12-slim

# Non-root runtime user; writable state lives only under /data.
RUN useradd --uid 10001 --create-home --home-dir /home/spaf spaf \
    && mkdir -p /data/logs && chown -R 10001:10001 /data

COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl "spaf[api,mcp]" \
    && rm -rf /tmp/*.whl

# Default to the zero-setup SQLite backend with all state under the /data volume.
ENV SPAF_DB_BACKEND=sqlite \
    SPAF_SQLITE_PATH=/data/spaf.db \
    SPAF_LOG_DIR=/data/logs \
    SPAF_AUDIT_LOG=/data/logs/audit.jsonl \
    SPAF_CACHE_PATH=/data/logs/ai_cache.db \
    PYTHONUNBUFFERED=1

USER 10001
WORKDIR /data
EXPOSE 8000

# Container healthcheck hits the open /health endpoint.
HEALTHCHECK --interval=30s --timeout=5s --retries=5 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=3).status==200 else 1)" || exit 1

ENTRYPOINT ["spaf", "serve", "--host", "0.0.0.0", "--port", "8000", "--scope-file", "/data/scope.json"]
