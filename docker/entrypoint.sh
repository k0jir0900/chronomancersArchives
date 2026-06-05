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
    app:app
