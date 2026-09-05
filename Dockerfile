# Prompt Firewall — single-container image: FastAPI service + bundled web UI.
#
#   docker build -t prompt-firewall .
#   docker run --rm -p 8000:8000 prompt-firewall
#
# or simply: docker compose up
#
# Works identically on Linux, macOS, and Windows (Docker Desktop / WSL2) —
# no host-specific setup required.

FROM python:3.11-slim AS runtime

# Fail fast on missing files, no .pyc clutter in the image, unbuffered logs
# so `docker logs` shows output immediately during a live demo.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Install dependencies first so this layer is cached across code-only changes.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Application code, library, CLI, and the static web UI.
COPY src/ ./src/
COPY webui/ ./webui/
COPY cli.py ./cli.py

# Run as a non-root user (least privilege — this container never needs root).
RUN useradd --create-home --uid 1000 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

# Container is only "healthy" once the API actually answers, not just once
# the process starts — catches a crashed/hung worker under `docker compose up`.
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:8000/health', timeout=2)" || exit 1

CMD ["uvicorn", "src.promptfirewall.api:app", "--host", "0.0.0.0", "--port", "8000"]
