# Chronomancers Archives

A Log Management and Rule Lifecycle Portal focused on compliance and history tracking.

### 🗄️ 1. Database Configuration
Before running the application, you must set up the MySQL database. Connect to your MySQL server and execute the following commands in order.

**Step A: Database & User Setup**
Copy, paste, and execute these commands to create the database and user:

```sql
CREATE DATABASE chronomancers_archives
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

CREATE USER 'chronomancers_user'@'%' IDENTIFIED BY 'chronomancers_pass';

GRANT ALL PRIVILEGES ON chronomancers_archives.* TO 'chronomancers_user'@'%';
FLUSH PRIVILEGES;

USE chronomancers_archives;
```

> [!WARNING]
> **Security Notice:** The password `'chronomancers_pass'` is a default example. It is strongly recommended to change this to a secure password in a production environment.

**Step B: Table Initialization**
Copy, paste, and execute the contents of the `sql/001_init.sql` file to create the required tables (`users` and `archives`).

**Step C: Environment Variables**
Modify the existing `.env` file in the root directory to match the credentials above:

```bash
DB_HOST=localhost
DB_PORT=3306
DB_NAME=chronomancers_archives
DB_USER=chronomancers_user
DB_PASSWORD=chronomancers_pass
```

**Step D: Launch Application**
Once the database and environment are configured, build and start the containers:

```bash
docker-compose up -d --build
```

**Access:**
The portal is served via Nginx on port 443 (HTTPS):
- URL: `https://localhost`
- *Note: You may need to accept the self-signed certificate if running locally.*

### 👤 2. Default User
Upon first launch, if checking the database reveals no existing users, a default administrator is created:

- **Username:** `admin`
- **Password:** `admin`

> [!WARNING]
> **Security Notice:** Change this password immediately after logging in (Profile > Appearance & Security).

### 📝 3. Registering a New Rule (Form Guide)
When logging a new event via the **Register** page, fill out the form using the following guidelines:

*   **Rule Name**: A concise, unique name for the detection rule (e.g., `Suspicious CLI Command`).
*   **Action Type**:
    *   `Creation`: Introducing a brand new rule.
    *   `Modification`: Tuning or updating an existing rule.
    *   `Elimination`: Deprecating or removing a rule.
*   **Rule Status**:
    *   `Active`: Rule is running in production.
    *   `Disabled`: Rule is turned off.
*   **Tuning Driver**: The primary reason for this change.
    *   `Maintenance`: Regular review or metadata update.
    *   `False Positive Correction`: Adjusting logic to reduce noise.
    *   `Hardening`: Creating more robust logic (anti-evasion).
    *   `New Use Case`: Addressing a new threat scenario.
*   **Associated Ticket**: Traceability ID (e.g., `JIRA-101`, `SNOW-505`).
*   **Description**: Brief narrative explaining the context of the change.
*   **Rule Content**: The code or queries defining the rule logic.

#### Recommended Format: Sigma
It is highly recommended to use the **Sigma** (YAML) format for the **Rule Content** field to ensure standardization.

**Template:**
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

### 🧪 4. Injecting Test Data (Optional)
To populate the database with mock rules, history, and user activity, you can execute the included data generation script. This is useful for testing the dashboard visualizations.

**Command:**
```bash
docker-compose exec chronomancers_archives python generate_data.py
```

---

## 🛠 Tech Stack
- **Backend**: Flask (Python 3.12)
- **Database**: MySQL 8.0
- **Frontend**: Jinja2, Bootstrap 5, Chart.js
- **Reverse Proxy**: Nginx (HTTPS/TLS)
- **Containerization**: Docker Compose
