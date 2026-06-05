# Operations

Runbook for running, deploying, and operating Chronomancers Archives.

## Environments and compose files

Three layers, merged by `docker compose`:

- `docker-compose.yml` - base definition (no host bind mount, DB port not published).
- `docker-compose.override.yml` - local development. Auto-merged. NOT versioned.
  Bind-mounts the source for live edits and publishes MySQL `3306` for local tools.
- `docker-compose.prod.yml` - production. Applied explicitly. No bind mount,
  secure cookies, resource limits.

## Running

Development (uses the override automatically):

```bash
make up           # docker compose up -d --build
make logs         # follow the app logs
make down
```

Production:

```bash
make prod         # docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

The portal listens on `http://localhost:5001`.

## Application server

The app is served by **gunicorn** (see `docker/entrypoint.sh`), not the Flask
dev server. A single worker is used because `app.py` starts an in-process
APScheduler at import time; multiple worker processes would duplicate the
scheduled jobs. Concurrency comes from threads:

- `GUNICORN_THREADS` (default 4)
- `GUNICORN_TIMEOUT` (default 120)

For local debugging outside Docker only, `python app.py` honours
`FLASK_DEBUG=true` to enable the reloader and debugger. Never set it in a
container exposed to the network.

## Logs

The app and gunicorn log to stdout/stderr. Rotation is handled by the Docker
logging driver, not inside the container. Configure retention on the host, e.g.:

```yaml
# daemon.json or per-service logging:
logging:
  driver: json-file
  options:
    max-size: "10m"
    max-file: "5"
```

Note: the "Log rotation" panel in the Backups page rotates *database backup
files* (`.sql`), not application logs.

## Secrets

- `SECRET_KEY` is generated on first start and persisted in the `app_secrets`
  volume. Pin a fixed value via the env var only if you need it shared across
  hosts.
- `.env` is local and not versioned. Copy it from `.env.example`.
- The MySQL root password is randomized per init; the app uses `DB_USER` /
  `DB_PASSWORD` only.

> If a real `DB_PASSWORD` was ever committed, rotate it: change it in `.env`,
> recreate the MySQL volume (or `ALTER USER`), and restart.

## Security flags

- `SESSION_COOKIE_SECURE` defaults to `false`. Set it to `true` (the prod
  compose does this) when serving over HTTPS so session cookies are only sent
  on secure connections.
- `TRUST_PROXY` defaults to `false`. Set it to `true` (the prod compose does
  this) only when running behind a trusted reverse proxy. It enables `ProxyFix`
  so `X-Forwarded-For`/`-Proto` are honored and the rate limiter and audit log
  key on the real client IP instead of the proxy IP. Leave it `false` when the
  app is directly reachable, or clients could spoof their address.
- CSRF protection (Flask-WTF) is enabled globally; all POST forms carry a
  `csrf_token` and JSON `fetch` POSTs send the `X-CSRFToken` header.
- Rate limiting (Flask-Limiter) guards `/login` and the API-key endpoints.
  Storage is in-memory (single worker); move to Redis if you scale out.

## Database init and migrations

SQL files in `docker/mysql/` run only on first init (empty volume). To apply a
later script to an existing database:

```bash
docker compose exec -T mysql sh -c 'mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE"' < docker/mysql/002_indexes.sql
```
