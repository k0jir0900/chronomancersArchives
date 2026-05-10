# Chronomancers Archives

A web portal for managing detection rule lifecycles - tracking creations, modifications, and eliminations with full history, diff comparison, and PDF reporting.

## Requirements

- Docker and Docker Compose

## Setup

### 1. Environment Variables

Copy the `.env` file and set your values:

```bash
# GENERAL
TZ=America/Santiago
SECRET_KEY=<generate a random secret key>

# DB
MYSQL_ROOT_PASSWORD=<secure password>
DB_HOST=mysql
DB_PORT=3306
DB_NAME=chronomancers_archives
DB_USER=chronomancers_user
DB_PASSWORD=<secure password>
```

### 2. Start

```bash
docker compose up -d
```

The portal runs at `http://localhost:5001`.

### 3. Default Credentials

On first launch a default admin user is created automatically:

- **Username:** `admin`
- **Password:** `admin`

> [!WARNING]
> Change this password immediately after logging in (Profile > Security).

### Existing Deployment - Add Indexes

If you have an existing database and want to apply the performance indexes introduced in `sql/002_indexes.sql`, connect to MySQL and run:

```bash
docker compose exec mysql mysql -u root -p chronomancers_archives < sql/002_indexes.sql
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
| WSGI | Gunicorn |
| Containerization | Docker Compose |
