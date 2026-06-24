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

The portal runs at `http://localhost:5001`. For production, gunicorn tuning,
logging, and security flags, see [docs/operations.md](docs/operations.md).

### 3. Default Credentials

On first launch a default admin user is created automatically:

- **Username:** `admin`
- **Password:** `admin`
- **Role:** `superadmin` (the base `admin` account is promoted to `superadmin` on startup, so it sees every company)

A default company, **Aconetwork**, is also seeded on first start and is the default selection when registering a CDU.

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
│   ├── entrypoint.sh     # app bootstrap: generates SECRET_KEY, then launches gunicorn
│   └── mysql/            # MySQL init scripts (run on first DB init)
├── docs/                 # operational documentation
│   └── operations.md
├── Dockerfile            # multi-stage build, runs as a non-root user
├── docker-compose.yml    # service definition
├── requirements.txt
└── .env.example
```

---

## Features

- **Dashboard** - Stats, activity histogram, tuning driver breakdown, and top rules chart with optional date filtering.
- **CDU Registration** - Log a rule lifecycle event (creation, modification, elimination) with structured metadata, scoped to a company.
- **Rules History** - Browse all rules, search by name/company/environment/status, view full event timeline per rule, export to PDF.
- **Version Diff** - Side-by-side comparison of any two versions of a rule's content.
- **MITRE Coverage** - ATT&CK technique coverage matrix per company and domain.
- **Multi-Company (multi-tenant)** - Every view is scoped by company. Non-superadmin users only see data for the companies assigned to them; a topbar selector switches the active company (or `All`) when more than one is assigned.
- **Companies** - Create, rename, activate/deactivate, and delete companies (admin and superadmin). Companies with existing CDUs are deactivated instead of deleted to preserve history.
- **Backups** - Create, download, restore, and schedule automated database backups (admin only).
- **User Management** - Create users, assign roles (User / Admin / Super Admin / Service / Third Party), assign companies, reset passwords (admin and superadmin).

---

## Roles & Access

Access is scoped by role and by company. Users only see CDU data for the companies assigned to them; superadmin is the only role that sees everything.

| Role | Sees | Administration menu | Company scope |
|---|---|---|---|
| **Super Admin** | All companies | Yes (Users, Companies, Backups, MITRE, Audit) | Unrestricted; selector lists every company plus `All` |
| **Admin** | Assigned companies | Yes (Users, Companies, Backups, MITRE, Audit) | Limited to assigned companies |
| **User** | Assigned companies | No | Limited to assigned companies |
| **Service** | - | No | Cannot log in via web |
| **Third Party** | - | No | Cannot log in via web |

Routes added with this access model:

| Route | Access | Purpose |
|---|---|---|
| `/companies` (+ `/companies/add`, `/edit/<id>`, `/delete/<id>`) | admin, superadmin | Company CRUD |
| `/users/<id>/companies` | admin, superadmin | Assign companies to a user |
| `/set-company` | any logged-in user | Switch the active company in the topbar selector |

> [!NOTE]
> A user with no company assigned sees no CDU data (fail-safe default). Assign at least one company, or use a superadmin account, to view data.

---

## Form Field Reference

| Field | Description |
|---|---|
| CDU Name | Unique name for the detection rule (e.g., `Suspicious CLI Command`) |
| Company | Organization the rule applies to; selected from the companies assigned to you (defaults to Aconetwork) |
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
| Server | Gunicorn (single worker, threaded) |
| Containerization | Docker (multi-stage build) + Docker Compose |
