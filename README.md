# Chronomancers Archives

A web portal for managing detection rule lifecycles - tracking creations, modifications, and eliminations with full history, diff comparison, and PDF reporting.

## Requirements

- Docker and Docker Compose

## Setup

### 1. Environment Variables

Copy the example file and fill in your values:

```bash
cp .env.example .env
```

Notes:

- `SECRET_KEY` is generated automatically on first start and persisted in the `app_secrets` volume. Leave it unset unless you want to pin a fixed value.
- The MySQL root password is randomized on init (`MYSQL_RANDOM_ROOT_PASSWORD`); the app connects with `DB_USER` / `DB_PASSWORD`, never root.

### 2. Build and Start

```bash
docker compose up -d --build
```

The portal runs at `http://localhost:5001`.

### 3. Default Credentials

On first launch a default admin user is created automatically:

- **Username:** `admin`
- **Password:** `admin`

> [!WARNING]
> Change this password immediately after logging in (Profile > Security).

### Existing Deployment - Add Indexes

The SQL files in `docker/mysql/` run automatically when the database is first initialized. To apply the performance indexes from `docker/mysql/002_indexes.sql` to an already-initialized database, run:

```bash
docker compose exec -T mysql sh -c 'mysql -u"$MYSQL_USER" -p"$MYSQL_PASSWORD" "$MYSQL_DATABASE"' < docker/mysql/002_indexes.sql
```

---

## Project Structure

```
.
├── src/                  # Flask application
│   ├── app.py
│   ├── generate_data.py
│   ├── reports_config.yaml
│   ├── templates/
│   └── static/
├── docker/               # container provisioning
│   ├── entrypoint.sh     # app bootstrap: generates SECRET_KEY, then launches the app
│   └── mysql/            # MySQL init scripts (run on first DB init)
├── Dockerfile            # multi-stage build, runs as a non-root user
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

---

## Features

- **Dashboard** - Stats, activity histogram, tuning driver breakdown, and top rules chart with optional date filtering.
- **CDU Registration** - Log a rule lifecycle event (creation, modification, elimination) with structured metadata.
- **Rules History** - Browse all rules, search by name/company/environment/status, view full event timeline per rule, export to PDF.
- **Version Diff** - Side-by-side comparison of any two versions of a rule's content.
- **Backups** - Create, download, restore, and schedule automated database backups (admin only).
- **User Management** - Create users, assign roles (User / Admin), reset passwords (admin only).

---

## Form Field Reference

| Field | Description |
|---|---|
| CDU Name | Unique name for the detection rule (e.g., `Suspicious CLI Command`) |
| Company | Organization the rule applies to |
| Environment | Deployment scope (e.g., `Production`, `Staging`) |
| Action Type | `creation` / `modification` / `elimination` |
| Rule Status | `active` - running in production / `disabled` - turned off |
| Tuning Driver | `maintenance` / `fp_correction` / `hardening` / `new_use_case` |
| Associated Ticket | Optional traceability ID (e.g., `JIRA-101`, `SNOW-505`) |
| Description | Context and rationale for the change |
| Rule Content | Rule logic - Sigma (YAML) format recommended |

### Sigma Template

```yaml
title: {Rule Title}
id: {UUID}
status: test
description: Detects specific anomaly.
author: {Author Name}
date: 2025-01-01
logsource:
    product: {Product}
    service: {Service}
detection:
    selection:
        condition: selection_string
    condition: selection
level: medium
```

---

## Test Data

Populate the database with mock rules and history for testing:

```bash
docker compose exec chronomancers_archives python generate_data.py
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Flask 3.0 (Python 3.12) |
| Database | MySQL 8.4 |
| Frontend | Bootstrap 5.3, Bootstrap Icons, Chart.js |
| Server | Flask dev server (Gunicorn available for production) |
| Containerization | Docker (multi-stage build) + Docker Compose |
