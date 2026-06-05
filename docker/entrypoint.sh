#!/bin/sh
set -e

# Ensure a SECRET_KEY exists.
# Priority: an explicit SECRET_KEY env var wins.
# Otherwise generate one once and persist it in the mounted secrets volume
# so it survives restarts and is shared across workers in this container.
SECRET_FILE="/run/secrets/secret_key"
if [ -z "$SECRET_KEY" ]; then
    mkdir -p /run/secrets
    if [ ! -s "$SECRET_FILE" ]; then
        python -c "import secrets; print(secrets.token_hex(32))" > "$SECRET_FILE"
        chmod 600 "$SECRET_FILE"
        echo "entrypoint: generated new SECRET_KEY at $SECRET_FILE"
    fi
    SECRET_KEY="$(cat "$SECRET_FILE")"
    export SECRET_KEY
fi

# Optional TLS. When ENABLE_SSL=true, generate a self-signed cert (once) from
# DOMAIN/DAYS, persist it in the mounted secrets volume, and serve gunicorn over
# HTTPS on 5001.
SSL_ARGS=""
if [ "$(echo "${ENABLE_SSL:-false}" | tr '[:upper:]' '[:lower:]')" = "true" ]; then
    CERT_DIR="/run/secrets/tls"
    CERT_FILE="$CERT_DIR/cert.pem"
    KEY_FILE="$CERT_DIR/key.pem"
    mkdir -p "$CERT_DIR"
    if [ ! -s "$CERT_FILE" ] || [ ! -s "$KEY_FILE" ]; then
        openssl req -x509 -newkey rsa:2048 -nodes \
            -keyout "$KEY_FILE" -out "$CERT_FILE" \
            -days "${DAYS:-825}" -subj "/CN=${DOMAIN:-localhost}" \
            -addext "subjectAltName=DNS:${DOMAIN:-localhost}"
        chmod 600 "$KEY_FILE"
        echo "entrypoint: generated self-signed cert for ${DOMAIN:-localhost} (${DAYS:-825} days)"
    fi
    SSL_ARGS="--certfile $CERT_FILE --keyfile $KEY_FILE"
fi

cd /app/src

# Single worker with threads: app.py starts an in-process APScheduler at import
# time, so multiple worker processes would duplicate the scheduled jobs.
# Concurrency comes from threads, not extra workers.
exec gunicorn \
    --bind 0.0.0.0:5001 \
    --workers 1 \
    --threads "${GUNICORN_THREADS:-4}" \
    --timeout "${GUNICORN_TIMEOUT:-120}" \
    --access-logfile - \
    --error-logfile - \
    $SSL_ARGS \
    app:app
