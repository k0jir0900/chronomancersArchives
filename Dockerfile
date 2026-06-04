# syntax=docker/dockerfile:1

# --- Build stage: install Python dependencies into an isolated prefix ---
FROM python:3.12-slim AS builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# --- Runtime stage: minimal image, non-root user ---
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY --from=builder /install /usr/local

# Non-root user; pre-create the secrets mount point and writable dirs with its ownership.
# A fresh named volume mounted on /run/secrets inherits this ownership on first use.
RUN useradd --create-home --uid 1000 appuser \
    && mkdir -p /run/secrets /app/src/static/uploads /app/src/backups \
    && chown -R appuser:appuser /run/secrets /app

WORKDIR /app
COPY --chown=appuser:appuser . .

WORKDIR /app/src

USER appuser
EXPOSE 5001

ENTRYPOINT ["sh", "/app/docker/entrypoint.sh"]
