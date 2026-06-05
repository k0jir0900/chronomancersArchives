<!--
Version: 1.3.0
Update this version on every modification of this file (SemVer: MAJOR.MINOR.PATCH).
-->

# CLAUDE.md

Base structure for new projects: working rules first, then the Docker-based
infrastructure template. Docker is the common substrate; the application layer
(Python, Node, Go, Java, ...) and the database (MySQL, PostgreSQL, ...) are
interchangeable.

---

# Part 1 - Working Rules

## Output

- Return code first. Explanation after, only if non-obvious.
- No inline prose. Comments only where logic is unclear.
- No boilerplate unless explicitly requested.

## Code Rules

- Simplest working solution. No over-engineering.
- No abstractions for single-use operations.
- No speculative features.
- Read the file before modifying it. Never edit blind.
- No docstrings or type annotations on code not being changed.
- No error handling for scenarios that cannot happen.
- Three similar lines beat a premature abstraction.
- Python runs only inside an environment (venv / virtualenv). Never install
  packages or run scripts against the global interpreter.

## Reusability & Structure

- If logic is usable in more than one place, extract it into a function or module.
- Pass dependencies explicitly as parameters.
- Break logic into small, focused functions. No monolithic blocks.

## Review Rules

- State the bug. Show the fix. Stop.
- No suggestions beyond the scope of the review.
- No compliments before or after.

## Debugging Rules

- Never speculate about a bug without reading the relevant code first.
- State what you found, where, and the fix. One pass.
- If the cause is unclear: say so. Do not guess.

## Formatting

- No em dashes, smart quotes, or decorative Unicode.
- Plain hyphens and straight quotes only.
- Natural language characters (accents, CJK, ...) are fine when content requires them.
- Code output must be copy-paste safe.

---

# Part 2 - Infrastructure (Docker Base)

Language-agnostic principles: separate application from infrastructure, keep
secrets out of the image, run as non-root, anchor paths, use connection pools,
and fail fast on missing configuration.

## 1. Guiding principle

Three layers, each file where its function belongs:

- **Application** (code and assets the runtime serves) -> `src/`
- **Container infrastructure** (bootstrap, DB init, log rotation) -> `docker/`
- **Orchestration / tooling** (Dockerfile, compose) -> root, where tools look by default.
- **Documentation** (guides, runbooks) -> `docs/`. The only documentation `.md`
  at the root is `README.md` (`CLAUDE.md` is project instructions, not docs);
  every other document lives under `docs/` and is linked from the README.

Two rules for any stack:
- `git` does not track junk, local data, or secrets.
- the image contains nothing the app does not need at runtime (no secrets, no
  `.git`, no build tools).

## 2. Directory layout

```
.
├── src/                      # application (any language)
│   ├── <entrypoint>          # app.py / index.js / main.go / Main.java ...
│   ├── <modules/packages>
│   ├── <config>.{yaml,json}  # config read by the code
│   └── <assets>/             # templates, static, public, etc. (if any)
├── docker/                   # container provisioning
│   ├── entrypoint.sh         # app container bootstrap
│   ├── wait-for.sh           # block until a dependency (host:port) is ready
│   ├── logrotate.sh          # in-container log rotation (installed at build)
│   └── db/                   # DB init scripts (mounted by the DB container)
├── docs/                     # documentation (only README.md + CLAUDE.md at root)
│   └── <guides>.md           # runbooks, tuning, operations
├── Dockerfile                # root
├── docker-compose.yml        # root
├── docker-compose.override.yml  # local dev overrides (NOT versioned)
├── docker-compose.prod.yml      # production overrides
├── Makefile                  # common command shortcuts (build, up, logs, ...)
├── <deps-manifest>           # requirements.txt / package.json / go.mod / pom.xml
├── .env.example              # variable template (no secrets)
├── .env                      # local, NOT versioned
├── .dockerignore
├── .gitignore
├── .gitattributes
└── README.md
```

Runtime data (uploads, backups, generated config) is created anchored to the
code under `src/` (section 4.2) and ignored by git.

## 3. Docker

Same layer regardless of language; only the contents of each stage change.

### 3.1 Multi-stage Dockerfile, non-root user

Pattern: a **build** stage that produces artifacts and a minimal **runtime**
stage that copies them and runs as an unprivileged user.

Interpreted (Python) - runtime uses a venv:

```dockerfile
# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder
WORKDIR /app
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PATH="/opt/venv/bin:$PATH"
COPY --from=builder /opt/venv /opt/venv
RUN useradd --create-home --uid 1000 appuser \
    && mkdir -p /run/secrets && chown -R appuser:appuser /run/secrets /app
WORKDIR /app
COPY --chown=appuser:appuser . .
WORKDIR /app/src
USER appuser
EXPOSE 8080
ENTRYPOINT ["sh", "/app/docker/entrypoint.sh"]
```

Interpreted (Node):

```dockerfile
# syntax=docker/dockerfile:1
FROM node:22-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build        # if applicable

FROM node:22-slim
ENV NODE_ENV=production
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app ./
USER node                # node:slim already ships a non-root "node" user
EXPOSE 8080
ENTRYPOINT ["sh", "/app/docker/entrypoint.sh"]
```

Compiled (Go), near-empty runtime:

```dockerfile
# syntax=docker/dockerfile:1
FROM golang:1.22 AS builder
WORKDIR /src
COPY go.* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /app/server ./cmd/server

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /app/server /server
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/server"]
```

Constants in all three:
- Multi-stage build: the final image carries no compilers or dependency cache.
- Non-root user: an RCE does not give root inside the container.
- No installing dependencies at runtime: restarts are fast and need no network.

### 3.2 entrypoint.sh

Container bootstrap. Logic that must run before the app (generate secrets, wait
for dependencies, light migrations). Keep it agnostic:

```sh
#!/bin/sh
set -e

# (secret auto-generation block, section 4.2, if applicable)

cd /app/src
exec "$@"          # the CMD or args define the real start command
```

If `ENTRYPOINT` invokes the binary directly (Go), this script may not exist.

`.sh` files must use LF line endings to run on Linux. Enforce via `.gitattributes`:

```
*.sh text eol=lf
```

### 3.3 .dockerignore vs .gitignore

Different files for different tools; Docker does **not** read `.gitignore`.

- `.gitignore`: what does not belong in the repository.
- `.dockerignore`: what does not belong in the image (size, build cache, and
  above all preventing a `COPY . .` from leaking `.env` or `.git` into the image).

A file can be in one, the other, or both:
- `.env`, runtime data -> both.
- `README.md`, `Dockerfile`, `.git`, DB init, local `node_modules` -> `.dockerignore` only.
- local editor config -> `.gitignore` only.

### 3.4 Healthcheck without extra dependencies

Use the runtime already in the image instead of installing `wget`/`curl`:

```yaml
# Python
test: ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')\" || exit 1"]
# Node
test: ["CMD-SHELL", "node -e \"require('http').get('http://127.0.0.1:8080/health',r=>process.exit(r.statusCode==200?0:1))\""]
# Binary with its own healthcheck (Go and similar)
test: ["CMD", "/server", "-healthcheck"]
```

### 3.5 docker-compose.yml (skeleton)

```yaml
services:
  db:
    image: <db-image>          # mysql:8.4 / postgres:16 / ...
    restart: unless-stopped
    environment:
      <DB_ENV>: ...            # engine-specific variables (section 5)
    expose:
      - "<db-port>"            # internal network only; do not publish to host if not needed
    volumes:
      - db_data:/var/lib/<engine>
      - ./docker/db:/docker-entrypoint-initdb.d:ro
    healthcheck:
      test: [ ... ]            # use the app user, not root
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 30s

  app:
    build: .
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
    working_dir: /app/src
    volumes:
      - .:/app                 # bind mount for development only (remove in production)
      - app_secrets:/run/secrets
    ports:
      - "8080:8080"
    environment:
      DB_HOST: ${DB_HOST}
      DB_PORT: ${DB_PORT}
      DB_NAME: ${DB_NAME}
      DB_USER: ${DB_USER}
      DB_PASSWORD: ${DB_PASSWORD}
    init: true

volumes:
  db_data:
  app_secrets:
```

- Do not publish the DB port to the host if only the app consumes it internally.
- The `.:/app` bind mount is for development (live reload). Remove in production
  and use only the image code.
- `depends_on: condition: service_healthy` keeps the app from starting before the DB.
- Optional services (reverse proxy/TLS, cache, scheduled jobs) are not part of
  the base. Add them as extra services when needed, or rely on the deployment
  environment (load balancer, managed cache). TLS is often terminated upstream.

### 3.6 wait-for.sh

Block startup until a dependency accepts TCP connections (a complement to
`depends_on`, which only waits for the container, not the service inside):

```sh
#!/bin/sh
# usage: wait-for.sh host:port -- command args
set -e
hostport="$1"; shift
[ "$1" = "--" ] && shift
host="${hostport%%:*}"; port="${hostport##*:}"
until nc -z "$host" "$port" 2>/dev/null; do
    echo "waiting for $host:$port..."; sleep 1
done
exec "$@"
```

### 3.7 Compose overrides

`docker compose` auto-merges `docker-compose.override.yml` on top of the base
file. Split concerns instead of branching one file:

- **base** (`docker-compose.yml`): shared definition, safe defaults.
- **override** (`docker-compose.override.yml`): local dev only (bind mounts,
  exposed ports, debug). Not versioned.
- **prod** (`docker-compose.prod.yml`): production (no bind mount, replicas,
  resource limits). Apply explicitly:

```sh
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### 3.8 Log rotation (in-container)

Rotate logs inside the image, not on the host: install the rotation tool at
**build** time and run it as the non-root app user. A startup hook
(`docker/logrotate.sh`) generates the config from environment variables and runs
the rotator on an interval in the background, before the main process starts.

- Configuration is changeable without rebuild: cadence, retention, compression,
  and size are env vars passed through compose (see section 4).
- State and the generated config live in a writable path (`/tmp`); the app user
  owns the logs, so no `su`/root step is needed.
- Use `copytruncate` when a process holds the log file descriptor open and does
  not reopen on signal (the safe default for shared log files).

## 4. Configuration and secrets

### 4.1 Rules

- **Never** hardcode secrets in code, the `Dockerfile`, or image layers.
- `.env` local, never versioned. Version `.env.example` as the template.
- The app must **fail at startup** if a required secret is missing, instead of
  falling back to an insecure default.

Fail-fast:

```python
# Python
import os
SECRET_KEY = os.getenv('SECRET_KEY') or _raise('SECRET_KEY is required')
```
```js
// Node
const SECRET_KEY = process.env.SECRET_KEY;
if (!SECRET_KEY) throw new Error('SECRET_KEY is required');
```
```go
// Go
secret := os.Getenv("SECRET_KEY")
if secret == "" { log.Fatal("SECRET_KEY is required") }
```

### 4.2 Auto-generating a secret at startup (optional)

When a secret should "create itself" without manual handling, do NOT generate it
at build time (it gets baked into a visible layer and changes on every rebuild).
Generate it at **startup** and persist it in a volume, preferring the environment
variable if present:

```sh
# fragment of docker/entrypoint.sh; use any generator available in the image
SECRET_FILE="/run/secrets/secret_key"
if [ -z "$SECRET_KEY" ]; then
    mkdir -p /run/secrets
    if [ ! -s "$SECRET_FILE" ]; then
        # openssl rand -hex 32   (alternative, no specific runtime)
        head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$SECRET_FILE"
        chmod 600 "$SECRET_FILE"
    fi
    SECRET_KEY="$(cat "$SECRET_FILE")"
    export SECRET_KEY
fi
```

Limitation: with multiple replicas each gets its own key. That needs a shared
volume or a secret manager (Vault, Docker/Swarm secrets, cloud secret manager).

## 5. Application layer (interchangeable)

### 5.1 Config by environment

All configuration enters via environment variables (12-factor). No hardcoded
hosts, ports, or credentials. Defaults only for non-sensitive values.

### 5.2 Python: environments only

Run Python exclusively inside a virtual environment, never the system
interpreter - locally and in the image.

```sh
python -m venv .venv
. .venv/bin/activate        # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

In Docker the venv lives at `/opt/venv` and is added to `PATH` (section 3.1).

### 5.3 Anchor paths to the module, not the cwd

So the app works regardless of where it is launched from:

```python
# Python
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
```
```js
// Node (ESM)
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
const BASE_DIR = dirname(fileURLToPath(import.meta.url));
```
In compiled binaries (Go, Rust) embed assets in the binary (`go:embed`),
avoiding runtime paths entirely.

### 5.4 Errors and logs

- Catch specific exceptions, not a catch-all that hides failures.
- Validate user input (dates, numbers, paths) before use, to avoid 500s.
- Use a leveled logger writing to stdout/stderr (log collectors read from there),
  not loose prints.

### 5.5 Production server

Never the framework dev server in production. Use a proper one: Gunicorn/uvicorn
(Python), the native server or PM2 (Node), the binary directly (Go). Disable debug.

## 6. Database layer (interchangeable)

### 6.1 Application user, not root/superuser

The app connects with a user privileged only on its own database. The superuser
is for administration, not for the app.

MySQL - root can be random and unknown:
```yaml
environment:
  MYSQL_RANDOM_ROOT_PASSWORD: "yes"
  MYSQL_DATABASE: ${DB_NAME}
  MYSQL_USER: ${DB_USER}
  MYSQL_PASSWORD: ${DB_PASSWORD}
```
PostgreSQL - define the superuser, create the app role separately (the init
script in 6.3 can create the scoped user):
```yaml
environment:
  POSTGRES_DB: ${DB_NAME}
  POSTGRES_USER: ${DB_USER}        # app role
  POSTGRES_PASSWORD: ${DB_PASSWORD}
```

### 6.2 Connection pool

One physical connection per request adds latency and exhausts sockets. Use a pool:

- Go: `database/sql` (`*sql.DB`) is already a pool; set `SetMaxOpenConns`.
- Node: `pg.Pool`, `mysql2/promise.createPool`.
- Python: drivers do not always pool; use the connector's pool or an ORM (SQLAlchemy).

With a pool, **always close** connections (they return to the pool). A leak drains it:

```
conn = pool.get()
try:
    # use conn
finally:
    conn.close()     # on EVERY path, including failure
```

### 6.3 Init scripts and migrations

- Schema init: files in `docker/db/`, mounted at `/docker-entrypoint-initdb.d`.
  They run only on an **empty** data volume (first init), not for later changes.
- Schema changes over time: use a versioned migration tool (Alembic, Flyway,
  golang-migrate, Prisma), do not edit the init scripts.

## 7. Security checklist

Before exposing the service to the network:

- [ ] Production server, not the dev server. Debug mode off.
- [ ] No default credentials. Generate or force a change on first access.
- [ ] Required secrets fail-fast, never a default value.
- [ ] Session cookies/tokens: security flags (HttpOnly, SameSite, Secure with HTTPS).
- [ ] CSRF protection on state-changing POST forms/endpoints.
- [ ] Rate limiting on login and sensitive endpoints.
- [ ] Always parameterized queries (never concatenate input into SQL).
- [ ] Containers run as non-root.
- [ ] Secrets out of the image and the repo (volume or secret manager).
- [ ] DB port not published to the host unless needed.
- [ ] File uploads validated (type and size) and served carefully.
- [ ] Base images pinned to a version and updated periodically.

## 8. New project checklist

1. Create `src/` (code) and `docker/` (`entrypoint.sh`, `wait-for.sh`, DB init).
2. Copy the templates: `Dockerfile`, `docker-compose.yml`, `.dockerignore`,
   `.gitignore`, `.gitattributes`, `.env.example`.
3. Pick the stack: adjust the `Dockerfile` stages and start command.
4. Pick the DB engine: adjust image, variables, and healthcheck.
5. Define variables in `.env` from `.env.example`.
6. `docker compose up -d --build` and verify healthchecks are green.
7. Walk the security checklist (section 7) before any reachable deployment.

## 9. File templates

### .env.example

```
# GENERAL
TZ=America/Santiago
# SECRET_KEY auto-generates at startup (entrypoint.sh) and persists in a volume.
# Set here only to pin a value.
# SECRET_KEY=

# DB
DB_HOST=db
DB_PORT=5432
DB_NAME=app_db
DB_USER=app_user
DB_PASSWORD=change_me_db_password

# Optional: connection pool size
# DB_POOL_SIZE=10
```

### .gitignore

```
# Local dependencies / build
__pycache__/
*.pyc
.venv/
node_modules/
dist/
build/

# Environment + local compose override
.env
docker-compose.override.yml

# Runtime (under src/)
src/uploads/
src/backups/
src/*.conf

# Logs
*.log

# OS / editor
.DS_Store
Thumbs.db
```

### .dockerignore

```
.git
.gitignore
.gitattributes
.dockerignore
Dockerfile
docker-compose.yml

# Secrets and runtime config
.env
docker-compose.override.yml
src/*.conf

# Local dependencies / build (generated in the image)
__pycache__/
*.pyc
.venv/
node_modules/
dist/
build/

# Runtime data (provided by volumes)
src/uploads/
src/backups/
*.log

# DB init: mounted by the DB container, not the app image
docker/db/

# Dev / docs
.claude/
*.md
```

### .gitattributes

```
* text=auto
*.sh text eol=lf
```
