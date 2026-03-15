# PromptSentinel — Backend Docker image
#
# IMPORTANT: CMD enforces --workers 1.
# The rate limiter defaults to in-memory state; multiple workers would each
# maintain separate counters, making per-IP limits ineffective.
# Set REDIS_URL before scaling horizontally (see DEPLOYMENT_CHECKLIST.md §3).

FROM python:3.12-slim

# Security: run as non-root
RUN addgroup --system promptsentinel && \
    adduser  --system --ingroup promptsentinel --no-create-home promptsentinel

WORKDIR /app

# Dependencies layer — rebuilt only when requirements.txt changes
COPY app/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Application source
COPY app/ ./app/

# Persistent-data mount point (set PROMPTSENTINEL_DB_PATH=/data/promptsentinel.db)
RUN mkdir /data && chown promptsentinel:promptsentinel /data
VOLUME ["/data"]

USER promptsentinel

EXPOSE 8000

# Liveness probe — load balancers and k8s use this automatically
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

# --workers 1 is required when REDIS_URL is not set (default).
# To scale: set REDIS_URL and increase --workers or use replicas.
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "1", \
     "--log-level", "info"]
