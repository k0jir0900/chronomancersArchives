import os
import secrets
import functools
import logging
import json
import atexit
import yaml
from flask import Flask, render_template, request, redirect, flash, session, url_for, send_file, jsonify, g, has_app_context
import mysql.connector
import mysql.connector.pooling
from datetime import datetime, timedelta
import calendar
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import urllib.request
import urllib.error
import threading
import signal

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.triggers.interval import IntervalTrigger
    scheduler_available = True
except ImportError:
    scheduler_available = False
    print("Warning: APScheduler not found. Scheduling features disabled.")

load_dotenv()

# Anchor file paths to this module's directory so they resolve regardless of cwd.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
if not app.secret_key:
    raise RuntimeError('SECRET_KEY environment variable is required')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'false').lower() == 'true'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
# Upper bound for an uploaded SQL backup (kept within MAX_CONTENT_LENGTH so the
# global request guard rejects anything larger first, with a friendly message here).
MAX_BACKUP_SIZE = 16 * 1024 * 1024
# Flask-WTF's HTTPS referer check compares the browser Referer against
# request.host (scheme + host + port). Some reverse proxies cannot present a
# Host that matches the public origin's host:port, which yields "The referrer
# does not match the host". Set CSRF_SSL_STRICT=false to drop that extra check;
# the CSRF token and SameSite=Lax cookie still protect state-changing requests.
app.config['WTF_CSRF_SSL_STRICT'] = os.getenv('CSRF_SSL_STRICT', 'true').lower() == 'true'
app.jinja_env.filters['split'] = lambda s, sep=',': s.split(sep)

# Trust X-Forwarded-* only behind a known reverse proxy (set TRUST_PROXY=true in
# that deployment). Without this, request.remote_addr is the proxy IP, so the
# rate limiter and audit log would see every client as the same address.
if os.getenv('TRUST_PROXY', 'false').lower() == 'true':
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

csrf = CSRFProtect(app)


@app.errorhandler(CSRFError)
def _handle_csrf_error(e):
    # Surface the exact reason (referer mismatch vs missing/invalid token) and the
    # values involved, so proxy misconfiguration can be diagnosed from the logs.
    app.logger.warning(
        "CSRF 400: %s | host=%s referer=%s secure=%s",
        e.description, request.host, request.referrer, request.is_secure,
    )
    return e.description, 400


# A modest global default protects every endpoint as defense in depth; sensitive
# routes (login, API key generation, the CDU export) set tighter explicit limits.
# Static assets and the health check are exempt so page loads and the container
# probe are never throttled. Behind a reverse proxy set TRUST_PROXY=true so the
# limiter keys on the real client IP and not the shared proxy address.
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[os.getenv('RATE_LIMIT_DEFAULT', '240 per minute')],
)


@limiter.request_filter
def _exempt_static_and_health():
    return request.endpoint in ('static', 'health')


# Content-Security-Policy and hardening headers. The CDN origins below match the
# <script>/<link> tags in the templates; 'unsafe-inline' is required for the inline
# scripts and onclick handlers still present in the templates (a nonce does not
# cover inline event-handler attributes). frame-ancestors/base-uri/object-src close
# off clickjacking and base-tag injection.
_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'"
)


@app.after_request
def _set_security_headers(resp):
    resp.headers.setdefault('Content-Security-Policy', _CSP)
    resp.headers.setdefault('X-Content-Type-Options', 'nosniff')
    resp.headers.setdefault('X-Frame-Options', 'DENY')
    resp.headers.setdefault('Referrer-Policy', 'same-origin')
    return resp

_TD_EXPAND = {'fp': 'False Positive', 'fn': 'False Negative', 'tp': 'True Positive', 'tn': 'True Negative'}
def _humanize_td(val):
    if not val or val == '—':
        return val or '—'
    return ' '.join(_TD_EXPAND.get(p.lower(), p.capitalize()) for p in str(val).split('_'))
app.jinja_env.filters['humanize_td'] = _humanize_td

UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# TLS cert location. Matches CERT_DIR in docker/entrypoint.sh (host-mounted folder
# so an uploaded cert survives restarts and can be inspected/replaced).
CERT_DIR = os.getenv('CERT_DIR', '/app/certs')

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
            filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

_db_pool = None

def _get_pool():
    global _db_pool
    if _db_pool is None:
        _db_pool = mysql.connector.pooling.MySQLConnectionPool(
            pool_name='chronomancers_pool',
            pool_size=int(os.getenv('DB_POOL_SIZE', 10)),
            pool_reset_session=True,
            host=os.getenv('DB_HOST'),
            port=os.getenv('DB_PORT'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            database=os.getenv('DB_NAME')
        )
    return _db_pool

def get_db_connection():
    try:
        conn = _get_pool().get_connection()
    except mysql.connector.Error as err:
        app.logger.error("DB pool connection error: %s", err)
        return None
    # Track per-request connections so the teardown hook always returns them to
    # the pool, even if a route forgets to close or the client aborts the request
    # (a self-signed cert makes browsers drop connections mid-request). Background
    # threads run without an app context and manage their own close().
    if has_app_context():
        g.setdefault('_db_conns', []).append(conn)
    return conn


@app.teardown_request
def _release_db_connections(exc=None):
    # Safety net against leaks: return pooled connections a route left open
    # (forgotten close or aborted request). Skip ones already returned -- a
    # PooledMySQLConnection sets _cnx=None on close(), and closing it twice would
    # make the pool spawn a brand-new connection (add_connection(None)).
    for conn in g.pop('_db_conns', []):
        if getattr(conn, '_cnx', None) is None:
            continue
        try:
            conn.close()
        except Exception:
            pass

MITRE_CONFIG_FILE = os.path.join(BASE_DIR, 'mitre.conf')

def load_mitre_config():
    if os.path.exists(MITRE_CONFIG_FILE):
        try:
            with open(MITRE_CONFIG_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, ValueError, OSError):
            return {}
    return {}

def save_mitre_config(config):
    with open(MITRE_CONFIG_FILE, 'w') as f:
        json.dump(config, f)

MITRE_DOMAINS = {
    'enterprise': {
        'label': 'Enterprise',
        'url': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json',
        'kill_chain': 'mitre-attack',
    },
    'ics': {
        'label': 'ICS / OT',
        'url': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json',
        'kill_chain': 'mitre-ics-attack',
    },
}

def get_mitre_domain_config(config, domain):
    # Legacy flat config (pre multi-domain) is treated as enterprise.
    if domain == 'enterprise' and 'enterprise' not in config and 'attack_version' in config:
        return config
    return config.get(domain, {})

def save_mitre_domain_config(domain, info):
    config = load_mitre_config()
    if 'enterprise' not in config and 'attack_version' in config:
        config = {'enterprise': dict(config)}
    config[domain] = info
    save_mitre_config(config)

REPORTS_CONFIG_FILE = os.path.join(BASE_DIR, 'reports_config.yaml')

def load_reports_config():
    if not os.path.exists(REPORTS_CONFIG_FILE):
        return []
    try:
        with open(REPORTS_CONFIG_FILE, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
            return data.get('reports', []) if data else []
    except Exception as e:
        app.logger.error("Error loading reports config: %s", e)
        return []

def build_report_data(config, company, date_from, date_to):
    conn = get_db_connection()
    if not conn:
        return None
    cursor = conn.cursor(dictionary=True)

    where_parts = []
    params = []
    if company:
        where_parts.append('company = %s')
        params.append(company)
    if date_from:
        where_parts.append('created_at >= %s')
        params.append(date_from + ' 00:00:00')
    if date_to:
        where_parts.append('created_at <= %s')
        params.append(date_to + ' 23:59:59')
    cf, cfp = company_filter()
    where_parts.append(cf)
    params.extend(cfp)

    where = ('WHERE ' + ' AND '.join(where_parts)) if where_parts else ''
    data  = {'sections': []}

    def _fmt_row(row):
        for k, v in row.items():
            if hasattr(v, 'strftime'):
                row[k] = v.strftime('%Y-%m-%d')
        return row

    try:
        for sec in config.get('sections', []):
            sec_type = sec.get('type', 'table')
            result   = {'id': sec.get('id', ''), 'title': sec.get('title', ''), 'type': sec_type}

            if sec_type in ('stats', 'table'):
                sql = (sec.get('query') or '').strip()
                if sql:
                    n = sql.count('{where}')
                    cursor.execute(sql.replace('{where}', where), params * n)
                    if sec_type == 'stats':
                        row = cursor.fetchone()
                        result['row'] = _fmt_row(row) if row else {}
                    else:
                        result['rows'] = [_fmt_row(r) for r in cursor.fetchall()]
                else:
                    result['row' if sec_type == 'stats' else 'rows'] = {} if sec_type == 'stats' else []

                if sec_type == 'table':
                    if result['id'] == 'actions':
                        existing = {r.get('action_type'): r.get('count', 0) for r in result['rows']}
                        result['rows'] = [
                            {'action_type': a, 'count': existing.get(a, 0)}
                            for a in ('creation', 'modification', 'elimination')
                        ]
                        result['rows'].sort(key=lambda r: r['count'], reverse=True)
                    elif result['id'] == 'tuning_driver':
                        cursor.execute(
                            "SELECT DISTINCT COALESCE(tuning_driver, 'unknown') AS tuning_driver "
                            "FROM archives WHERE tuning_driver IS NOT NULL"
                        )
                        all_drivers = [r['tuning_driver'] for r in cursor.fetchall()]
                        existing = {r.get('tuning_driver'): r.get('count', 0) for r in result['rows']}
                        for d in existing:
                            if d not in all_drivers:
                                all_drivers.append(d)
                        result['rows'] = [
                            {'tuning_driver': d, 'count': existing.get(d, 0)}
                            for d in all_drivers
                        ]
                        result['rows'].sort(key=lambda r: r['count'], reverse=True)

            elif sec_type == 'mitre':
                mitre_parts = list(where_parts) + ["mitre IS NOT NULL", "mitre != 'null'", "mitre != '[]'"]
                mitre_where = 'WHERE ' + ' AND '.join(mitre_parts)
                cursor.execute(f"SELECT mitre FROM archives {mitre_where}", params)
                counts = {}
                for row in cursor.fetchall():
                    try:
                        techs = json.loads(row['mitre']) if isinstance(row['mitre'], str) else (row['mitre'] or [])
                        for t in techs:
                            base = t.split(':')[0]
                            counts[base] = counts.get(base, 0) + 1
                    except Exception:
                        pass
                top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:15]
                if top:
                    ids = [t[0] for t in top]
                    cursor.execute(
                        "SELECT technique_id, name, tactic FROM mitre_techniques WHERE technique_id IN (%s)"
                        % ','.join(['%s'] * len(ids)), ids
                    )
                    nm = {r['technique_id']: r for r in cursor.fetchall()}
                    result['rows'] = [
                        {'id': t[0], 'count': t[1],
                         'name': nm.get(t[0], {}).get('name', ''),
                         'tactic': (nm.get(t[0], {}).get('tactic') or '').split(',')[0].strip()}
                        for t in top
                    ]
                else:
                    result['rows'] = []

            elif sec_type == 'timeline':
                cursor.execute(
                    f"SELECT DATE(created_at) AS date, action_type, COUNT(*) AS count "
                    f"FROM archives {where} GROUP BY DATE(created_at), action_type ORDER BY date",
                    params
                )
                tl = {}
                for row in cursor.fetchall():
                    d = str(row['date'])
                    tl.setdefault(d, {'creation': 0, 'modification': 0, 'elimination': 0})
                    tl[d][row['action_type']] = row['count']
                if date_from or date_to or tl:
                    from datetime import date as _date, timedelta
                    all_dates = sorted(tl.keys())
                    start = _date.fromisoformat(date_from) if date_from else (_date.fromisoformat(all_dates[0]) if all_dates else None)
                    end   = _date.fromisoformat(date_to)   if date_to   else (_date.fromisoformat(all_dates[-1]) if all_dates else None)
                    if start and end:
                        cur = start
                        while cur <= end:
                            tl.setdefault(cur.isoformat(), {'creation': 0, 'modification': 0, 'elimination': 0})
                            cur += timedelta(days=1)
                result['rows'] = [{'date': d, **v} for d, v in sorted(tl.items())]

            data['sections'].append(result)

    except Exception as e:
        app.logger.error("Report build error: %s", e)
        data['error'] = str(e)
    finally:
        cursor.close()
        conn.close()

    return data

def sync_mitre_data(domain='enterprise'):
    if domain not in MITRE_DOMAINS:
        app.logger.warning("MITRE sync: unknown domain %s", domain)
        return False
    url = MITRE_DOMAINS[domain]['url']
    kill_chain = MITRE_DOMAINS[domain]['kill_chain']
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'chronomancers-archives/1.0'})
        with urllib.request.urlopen(req, timeout=120) as response:
            data = json.loads(response.read().decode('utf-8'))
    except Exception as e:
        app.logger.error("MITRE sync fetch error: %s", e)
        return False

    attack_version = None
    spec_version = None
    for obj in data.get('objects', []):
        if obj.get('type') == 'x-mitre-collection':
            attack_version = obj.get('x_mitre_version')
            spec_version = obj.get('x_mitre_attack_spec_version')
            break

    techniques = []
    for obj in data.get('objects', []):
        if obj.get('type') != 'attack-pattern':
            continue
        if obj.get('x_mitre_deprecated', False) or obj.get('revoked', False):
            continue

        tech_id = None
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == 'mitre-attack':
                tech_id = ref.get('external_id')
                break

        if not tech_id or not tech_id.startswith('T'):
            continue

        name = obj.get('name', '')
        is_subtechnique = obj.get('x_mitre_is_subtechnique', False)
        tactics = [p['phase_name'] for p in obj.get('kill_chain_phases', [])
                   if p.get('kill_chain_name') == kill_chain]
        tactic_str = ','.join(tactics) if tactics else None
        parent_id = tech_id.split('.')[0] if is_subtechnique and '.' in tech_id else None

        techniques.append((tech_id, name, tactic_str, parent_id, domain))

    if not techniques:
        return False

    conn = get_db_connection()
    if not conn:
        return False

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT GET_LOCK(%s, 0) AS acquired", (f'mitre_sync_lock_{domain}',))
        row = cursor.fetchone()
        if not row or not row[0]:
            cursor.close()
            conn.close()
            return False

        try:
            cursor.execute("DELETE FROM mitre_techniques WHERE domain = %s", (domain,))
            cursor.executemany(
                "INSERT INTO mitre_techniques (technique_id, name, tactic, parent_id, domain) VALUES (%s, %s, %s, %s, %s)",
                techniques
            )
            cursor.execute("DELETE FROM mitre_sync WHERE domain = %s", (domain,))
            cursor.execute("INSERT INTO mitre_sync (last_updated, domain) VALUES (NOW(), %s)", (domain,))
            conn.commit()
            total = len(techniques)
            subs = sum(1 for t in techniques if t[3] is not None)
            save_mitre_domain_config(domain, {
                'attack_version': attack_version,
                'spec_version': spec_version,
                'total_techniques': total - subs,
                'total_subtechniques': subs,
                'last_sync': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'source': url,
            })
            app.logger.info("MITRE sync complete (%s): %s techniques stored", domain, total)
            return True
        except Exception as e:
            app.logger.error("MITRE DB error: %s", e)
            return False
        finally:
            cursor.execute("SELECT RELEASE_LOCK(%s)", (f'mitre_sync_lock_{domain}',))
            cursor.fetchone()
    finally:
        cursor.close()
        conn.close()


def sync_all_mitre():
    for domain in MITRE_DOMAINS:
        sync_mitre_data(domain)


def startup_mitre_check():
    try:
        conn = get_db_connection()
        if not conn:
            return
        cursor = conn.cursor(dictionary=True)
        for domain in MITRE_DOMAINS:
            cursor.execute(
                "SELECT last_updated FROM mitre_sync WHERE domain = %s ORDER BY id DESC LIMIT 1",
                (domain,)
            )
            row = cursor.fetchone()
            cursor.execute("SELECT COUNT(*) as cnt FROM mitre_techniques WHERE domain = %s", (domain,))
            count_row = cursor.fetchone()

            needs_sync = True
            if row and row['last_updated'] and count_row and count_row['cnt'] > 0:
                days_since = (datetime.now() - row['last_updated']).days
                needs_sync = days_since >= 7

            if needs_sync:
                app.logger.info("Starting MITRE ATT&CK background sync (%s)...", domain)
                t = threading.Thread(target=sync_mitre_data, args=(domain,), daemon=True)
                t.start()
        cursor.close()
        conn.close()
    except Exception as e:
        app.logger.error("MITRE startup check error: %s", e)


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

def init_db():
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS api_audit_log (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NULL,
                api_key_id INT NULL,
                action VARCHAR(50) DEFAULT 'api_call',
                ip_address VARCHAR(45),
                endpoint VARCHAR(255),
                params TEXT,
                status_code INT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_audit_created (created_at),
                INDEX idx_audit_user (user_id)
            )
        """)
        try:
            cursor.execute("ALTER TABLE api_audit_log MODIFY COLUMN status_code INT NULL")
        except mysql.connector.Error:
            pass
        try:
            cursor.execute("ALTER TABLE api_audit_log ADD COLUMN action VARCHAR(50) DEFAULT 'api_call' AFTER api_key_id")
        except mysql.connector.Error:
            pass
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN is_active TINYINT NOT NULL DEFAULT 1")
        except mysql.connector.Error:
            pass
        # Migrate roles to lowercase
        try:
            cursor.execute("UPDATE users SET role = LOWER(role) WHERE role != LOWER(role)")
        except mysql.connector.Error:
            pass
        try:
            cursor.execute("ALTER TABLE archives ADD COLUMN mitre JSON NULL")
        except mysql.connector.Error:
            pass
        try:
            cursor.execute("ALTER TABLE archives ADD COLUMN siem VARCHAR(50) NULL")
        except mysql.connector.Error:
            pass
        try:
            cursor.execute("ALTER TABLE archives ADD COLUMN tags JSON NULL")
        except mysql.connector.Error:
            pass
        try:
            cursor.execute("ALTER TABLE archives ADD COLUMN severity VARCHAR(20) NULL")
        except mysql.connector.Error:
            pass
        try:
            cursor.execute("ALTER TABLE mitre_techniques ADD COLUMN domain VARCHAR(20) NOT NULL DEFAULT 'enterprise'")
        except mysql.connector.Error:
            pass
        try:
            cursor.execute("ALTER TABLE mitre_techniques DROP INDEX technique_id")
        except mysql.connector.Error:
            pass
        try:
            cursor.execute("ALTER TABLE mitre_techniques ADD UNIQUE KEY uniq_tech_domain (technique_id, domain)")
        except mysql.connector.Error:
            pass
        try:
            cursor.execute("ALTER TABLE mitre_sync ADD COLUMN domain VARCHAR(20) NOT NULL DEFAULT 'enterprise'")
        except mysql.connector.Error:
            pass
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tags_pool (
                id INT AUTO_INCREMENT PRIMARY KEY,
                category VARCHAR(50) NOT NULL,
                value VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uniq_cat_value (category, value),
                INDEX idx_tag_category (category)
            )
        """)
        seed_tags = [
            ('baseline', 'gold'), ('baseline', 'silver'), ('baseline', 'bronze'), ('baseline', 'custom'),
            ('hardware_family', 'server'), ('hardware_family', 'workstation'), ('hardware_family', 'network_device'),
            ('hardware_family', 'mobile'), ('hardware_family', 'iot'), ('hardware_family', 'scada'), ('hardware_family', 'plc'),
            ('os_family', 'windows'), ('os_family', 'linux'), ('os_family', 'macos'), ('os_family', 'unix'),
            ('os_family', 'android'), ('os_family', 'ios'), ('os_family', 'embedded'),
            ('network_family', 'firewall'), ('network_family', 'router'), ('network_family', 'switch'),
            ('network_family', 'load_balancer'), ('network_family', 'proxy'), ('network_family', 'ids_ips'),
            ('application_family', 'web'), ('application_family', 'database'), ('application_family', 'email'),
            ('application_family', 'file_share'), ('application_family', 'identity'),
            ('application_family', 'virtualization'), ('application_family', 'container'),
            ('vendor', 'microsoft'), ('vendor', 'cisco'), ('vendor', 'palo_alto'), ('vendor', 'fortinet'),
            ('vendor', 'vmware'), ('vendor', 'redhat'), ('vendor', 'ubuntu'), ('vendor', 'debian'), ('vendor', 'oracle'),
            ('criticality', 'critical'), ('criticality', 'high'), ('criticality', 'medium'), ('criticality', 'low'),
        ]
        cursor.executemany(
            "INSERT IGNORE INTO tags_pool (category, value) VALUES (%s, %s)",
            seed_tags
        )
        # --- Multi-company (multi-tenant) schema ---
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS companies (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL UNIQUE,
                is_active TINYINT NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_companies (
                user_id INT NOT NULL,
                company_id INT NOT NULL,
                PRIMARY KEY (user_id, company_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE
            )
        """)
        try:
            cursor.execute("ALTER TABLE archives ADD COLUMN company_id INT NULL")
        except mysql.connector.Error:
            pass
        try:
            cursor.execute("ALTER TABLE archives ADD INDEX idx_company_id (company_id)")
        except mysql.connector.Error:
            pass
        # Default company, plus backfill from existing free-text company values.
        cursor.execute("INSERT IGNORE INTO companies (name) VALUES ('Aconetwork')")
        cursor.execute("""
            INSERT IGNORE INTO companies (name)
            SELECT DISTINCT company FROM archives
            WHERE company IS NOT NULL AND company <> ''
        """)
        cursor.execute("""
            UPDATE archives a
            JOIN companies c ON a.company = c.name
            SET a.company_id = c.id
            WHERE a.company_id IS NULL
        """)
        # Promote the base admin account to superadmin (sees every company).
        cursor.execute("UPDATE users SET role = 'superadmin' WHERE username = 'admin' AND role = 'admin'")
        hashed_password = generate_password_hash('admin')
        cursor.execute(
            "INSERT IGNORE INTO users (username, full_name, password_hash, role) VALUES (%s, %s, %s, %s)",
            ('admin', 'Admin', hashed_password, 'superadmin')
        )
        conn.commit()
        if cursor.rowcount:
            app.logger.info("Default admin user created.")

        # Mark the base admin as protected: it can be disabled but never deleted.
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN is_protected TINYINT NOT NULL DEFAULT 0")
        except mysql.connector.Error:
            pass
        cursor.execute("UPDATE users SET is_protected = 1 WHERE username = 'admin'")
        conn.commit()

        cursor.close()
        conn.close()

def _load_current_user(user_id):
    conn = get_db_connection()
    if not conn:
        return None
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id, username, full_name, role, profile_pic, theme_preference FROM users WHERE id = %s", (user_id,))
        return cursor.fetchone()
    except mysql.connector.Error:
        try:
            cursor.execute("SELECT id, username, role, profile_pic FROM users WHERE id = %s", (user_id,))
            return cursor.fetchone()
        except mysql.connector.Error:
            cursor.execute("SELECT id, username, role FROM users WHERE id = %s", (user_id,))
            return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

def _current_user():
    """Per-request cached current user (id, username, role, ...) or None."""
    if 'user_id' not in session:
        return None
    if not hasattr(g, 'current_user'):
        g.current_user = _load_current_user(session['user_id'])
    return g.current_user

@app.context_processor
def inject_user():
    return dict(current_user=_current_user())


@app.context_processor
def inject_static_versioning():
    # Append the file's mtime as a ?v= query so a changed CSS/JS gets a new URL
    # and browsers refetch it instead of serving a stale cached copy.
    def static_url(filename):
        try:
            v = int(os.path.getmtime(os.path.join(app.static_folder, filename)))
        except OSError:
            v = 0
        return url_for('static', filename=filename, v=v)
    return dict(static_url=static_url)


def _compute_allowed_company_ids():
    """None = unrestricted (superadmin). Otherwise the list of company_id the
    current user is assigned to ([] = assigned to none -> sees nothing)."""
    user = _current_user()
    if not user:
        return []
    if user.get('role') == 'superadmin':
        return None
    conn = get_db_connection()
    if not conn:
        return []
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT company_id FROM user_companies WHERE user_id = %s", (user['id'],))
        return [r[0] for r in cursor.fetchall()]
    finally:
        cursor.close()
        conn.close()


def allowed_company_ids():
    """Per-request cached result of _compute_allowed_company_ids()."""
    if not hasattr(g, '_allowed_company_ids'):
        g._allowed_company_ids = _compute_allowed_company_ids()
    return g._allowed_company_ids


def company_filter(alias=''):
    """(sql_fragment, params) scoping `archives` to the companies the request may
    see, honoring the active-company selector (session['active_company']).
    Always returns a fragment usable inside a WHERE/AND."""
    prefix = (alias + '.') if alias else ''
    allowed = allowed_company_ids()
    active = session.get('active_company', 'all')

    if allowed is None:
        if active != 'all':
            try:
                return (f"{prefix}company_id = %s", [int(active)])
            except (ValueError, TypeError):
                pass
        return ('1=1', [])

    if not allowed:
        return ('1=0', [])

    ids = list(allowed)
    if active != 'all':
        try:
            active_id = int(active)
            if active_id in allowed:
                ids = [active_id]
        except (ValueError, TypeError):
            pass
    placeholders = ','.join(['%s'] * len(ids))
    return (f"{prefix}company_id IN ({placeholders})", ids)


def visible_companies():
    """[{id, name}] of active companies the current request may see, by name."""
    allowed = allowed_company_ids()
    if allowed is not None and not allowed:
        return []
    conn = get_db_connection()
    if not conn:
        return []
    cursor = conn.cursor(dictionary=True)
    try:
        if allowed is None:
            cursor.execute("SELECT id, name FROM companies WHERE is_active = 1 ORDER BY name")
        else:
            ph = ','.join(['%s'] * len(allowed))
            cursor.execute(
                f"SELECT id, name FROM companies WHERE is_active = 1 AND id IN ({ph}) ORDER BY name",
                tuple(allowed)
            )
        return cursor.fetchall()
    finally:
        cursor.close()
        conn.close()


@app.context_processor
def inject_company_context():
    if 'user_id' not in session:
        return {}
    cos = visible_companies()
    role = (_current_user() or {}).get('role')
    return dict(
        nav_companies=cos,
        active_company=session.get('active_company', 'all'),
        show_company_selector=(role == 'superadmin' or len(cos) > 1),
    )


@app.route('/set-company', methods=['POST'])
@login_required
def set_company():
    choice = request.form.get('company', 'all')
    if choice == 'all':
        session['active_company'] = 'all'
    else:
        allowed = allowed_company_ids()
        try:
            cid = int(choice)
        except (ValueError, TypeError):
            cid = None
        if cid is not None and (allowed is None or cid in allowed):
            session['active_company'] = str(cid)
        else:
            session['active_company'] = 'all'
    return redirect(request.referrer or url_for('home'))

# Single source of truth for the time-range presets used across the app
# (Home, Reports). The dropdown labels live in templates/macros.html and the
# client-side date math in static/js/app.js; keep all three in sync.
PRESET_KEYS = ['week', 'lastweek', 'month', '7d', '30d', '90d']


def preset_date_range(key, today=None):
    """(from_iso, to_iso) for a named preset, or ('', '') for All time."""
    today = today or datetime.now().date()
    if key == 'week':
        f = today - timedelta(days=today.weekday())
        t = today + timedelta(days=6 - today.weekday())
    elif key == 'lastweek':
        f = today - timedelta(days=today.weekday() + 7)
        t = today - timedelta(days=today.weekday() + 1)
    elif key == 'month':
        f = today.replace(day=1)
        t = (f + timedelta(days=32)).replace(day=1) - timedelta(days=1)
    elif key in ('7d', '30d', '90d'):
        f = today - timedelta(days=int(key[:-1]))
        t = today
    else:
        return ('', '')
    return (f.isoformat(), t.isoformat())


def detect_preset(date_from, date_to, today=None):
    """Reverse of preset_date_range: which preset key matches the given range."""
    for k in PRESET_KEYS:
        if (date_from, date_to) == preset_date_range(k, today):
            return k
    return ''


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))

@app.route('/home')
@login_required
def home():
    conn = get_db_connection()
    if not conn:
        flash('Database connection failed.', 'error')
        return render_template('home.html')
    
    cursor = conn.cursor(dictionary=True)
    cf, cfp = company_filter()

    # Default preset across menus is "This week".
    default_start, default_end = preset_date_range('week')

    start_date = request.args.get('start_date', default_start)
    end_date = request.args.get('end_date', default_end)

    if not start_date and not end_date:
        # "All time" preset: span from the first record to today so the rest of
        # the route (BETWEEN queries, daily chart axis) keeps working unchanged.
        preset_key = ''
        cursor.execute(f"SELECT MIN(DATE(created_at)) AS first FROM archives WHERE {cf}", tuple(cfp))
        first = cursor.fetchone()['first']
        start_date = first.isoformat() if first else default_start
        end_date = default_end
    else:
        try:
            datetime.strptime(start_date, '%Y-%m-%d')
            datetime.strptime(end_date, '%Y-%m-%d')
        except ValueError:
            start_date, end_date = default_start, default_end
        preset_key = detect_preset(start_date, end_date)

    filters = {
        'start_date': start_date,
        'end_date': end_date,
        'preset_key': preset_key
    }
    
    cursor.execute(f"SELECT COUNT(DISTINCT rule_name) as unique_total FROM archives WHERE {cf}", tuple(cfp))
    unique_rules_count = cursor.fetchone()['unique_total']

    cursor.execute(f"SELECT COUNT(*) as total FROM archives WHERE created_at BETWEEN %s AND %s AND {cf}", (start_date + ' 00:00:00', end_date + ' 23:59:59') + tuple(cfp))
    total_events = cursor.fetchone()['total']

    cursor.execute(f"SELECT action_type, COUNT(*) as count FROM archives WHERE created_at BETWEEN %s AND %s AND {cf} GROUP BY action_type", (start_date + ' 00:00:00', end_date + ' 23:59:59') + tuple(cfp))
    action_counts = {row['action_type']: row['count'] for row in cursor.fetchall()}
    
    stats = {
        'unique_rules': unique_rules_count,
        'total': total_events,
        'creation': action_counts.get('creation', 0),
        'modification': action_counts.get('modification', 0),
        'elimination': action_counts.get('elimination', 0)
    }
    
    cursor.execute(f"SELECT rule_name, COUNT(*) as count FROM archives WHERE {cf} GROUP BY rule_name ORDER BY count DESC LIMIT 5", tuple(cfp))
    top_rules = cursor.fetchall()

    cursor.execute(f"SELECT tuning_driver, COUNT(*) as count FROM archives WHERE tuning_driver IS NOT NULL AND tuning_driver != '' AND created_at BETWEEN %s AND %s AND {cf} GROUP BY tuning_driver", (start_date + ' 00:00:00', end_date + ' 23:59:59') + tuple(cfp))
    tuning_drivers = cursor.fetchall()
    
    driver_map = {
        'fp_correction': 'False Positive',
        'hardening': 'Hardening',
        'new_use_case': 'New Use Case',
        'maintenance': 'Maintenance'
    }
    
    tuning_driver_data = {
        'labels': [driver_map.get(row['tuning_driver'], row['tuning_driver'].replace('_', ' ').title()) for row in tuning_drivers],
        'counts': [row['count'] for row in tuning_drivers]
    }
    
    cursor.execute(f"""
        SELECT DATE(created_at) as log_date, action_type, COUNT(*) as count
        FROM archives
        WHERE created_at BETWEEN %s AND %s AND {cf}
        GROUP BY log_date, action_type
        ORDER BY log_date ASC
    """, (start_date + ' 00:00:00', end_date + ' 23:59:59') + tuple(cfp))
    daily_rows = cursor.fetchall()
    
    start_dt = datetime.strptime(start_date, '%Y-%m-%d').date()
    end_dt = datetime.strptime(end_date, '%Y-%m-%d').date()
    dates = []
    cur = start_dt
    while cur <= end_dt:
        dates.append(str(cur))
        cur += timedelta(days=1)

    chart_data = {
        'labels': dates,
        'datasets': {
            'creation': [0] * len(dates),
            'modification': [0] * len(dates),
            'elimination': [0] * len(dates)
        }
    }

    date_to_idx = {d: i for i, d in enumerate(dates)}
    
    for row in daily_rows:
        d = str(row['log_date'])
        a = row['action_type']
        c = row['count']
        if d in date_to_idx and a in chart_data['datasets']:
            chart_data['datasets'][a][date_to_idx[d]] = c

    cursor.execute(f"""
        SELECT
            SUM(CASE WHEN a.mitre IS NOT NULL AND a.mitre != 'null' AND a.mitre != '[]' THEN 1 ELSE 0 END) as with_mitre,
            SUM(CASE WHEN a.mitre IS NULL OR a.mitre = 'null' OR a.mitre = '[]' THEN 1 ELSE 0 END) as without_mitre
        FROM archives a
        JOIN (SELECT rule_name, MAX(id) AS max_id FROM archives WHERE {cf} GROUP BY rule_name) latest ON a.id = latest.max_id
    """, tuple(cfp))
    mitre_row = cursor.fetchone()
    mitre_coverage = {
        'with_mitre': int(mitre_row['with_mitre'] or 0),
        'without_mitre': int(mitre_row['without_mitre'] or 0)
    }

    cursor.close()
    conn.close()

    return render_template('home.html', stats=stats, top_rules=top_rules, tuning_driver_data=tuning_driver_data, chart_data=chart_data, filters=filters, mitre_coverage=mitre_coverage)

@app.route('/history')
@login_required
def history():
    conn = get_db_connection()
    if not conn:
        flash('Database connection failed.', 'error')
        return redirect(url_for('home'))

    cursor = conn.cursor(dictionary=True)
    cf, cfp = company_filter()

    cursor.execute(f"SELECT DISTINCT rule_name FROM archives WHERE {cf} ORDER BY rule_name", tuple(cfp))
    rules = [row['rule_name'] for row in cursor.fetchall()]

    companies = [c['name'] for c in visible_companies()]

    cursor.execute(f"SELECT DISTINCT environment FROM archives WHERE {cf} ORDER BY environment", tuple(cfp))
    environments = [row['environment'] for row in cursor.fetchall()]

    cursor.execute(f"""
        SELECT a.rule_name, a.company, a.environment, a.rule_status, a.mitre,
               c.version
        FROM archives a
        JOIN (
            SELECT rule_name, company, environment, MAX(id) AS max_id, COUNT(*) AS version
            FROM archives
            WHERE {cf}
            GROUP BY rule_name, company, environment
        ) c ON a.id = c.max_id
        ORDER BY a.rule_name
    """, tuple(cfp))
    all_rules_metadata = cursor.fetchall()
    for row in all_rules_metadata:
        m = row.get('mitre')
        if isinstance(m, str):
            try:
                m = json.loads(m)
            except (json.JSONDecodeError, ValueError):
                m = None
        row['has_mitre'] = bool(m)

    selected_rule = request.args.get('cdu_name') or request.args.get('rule_name')
    selected_company = request.args.get('company')
    selected_environment = request.args.get('environment')
    selected_status = request.args.get('status')

    timeline_data = []
    summary = {}

    conditions = []
    params = []
    
    if selected_rule:
        conditions.append("rule_name = %s")
        params.append(selected_rule)
    if selected_company:
        conditions.append("company = %s")
        params.append(selected_company)
    if selected_environment:
        conditions.append("environment = %s")
        params.append(selected_environment)
    if selected_status:
        conditions.append("LOWER(rule_status) = LOWER(%s)")
        params.append(selected_status)

    if conditions:
        query_conditions = " AND ".join(conditions + [cf])
        cursor.execute(f"SELECT * FROM archives WHERE {query_conditions} ORDER BY created_at DESC", tuple(params) + tuple(cfp))
        timeline_data = cursor.fetchall()
        
        if timeline_data:
            latest = timeline_data[0]
            oldest = timeline_data[-1]
            
            title_parts = [r for r in [selected_rule, selected_company, selected_environment] if r]
            title = ' - '.join(title_parts) if len(title_parts) > 0 else 'Multiple Rules'
            
            summary = {
                'rule_name': title,
                'first_created': oldest['created_at'],
                'last_modified': latest['created_at'],
                'current_status': latest['rule_status'],
                'current_severity': latest.get('severity'),
                'total_events': len(timeline_data),
                'creator': oldest.get('modified_by', 'Unknown'),
                'last_modifier': latest.get('modified_by', 'Unknown'),
                'company': latest.get('company', 'N/A'),
                'environment': latest.get('environment', 'N/A')
            }
            
            start_date = oldest['created_at'].replace(day=1)
            last_day = calendar.monthrange(latest['created_at'].year, latest['created_at'].month)[1]
            end_date = latest['created_at'].replace(day=last_day)
            
            chart_query = f"""
                SELECT 
                    DATE(created_at) as date,
                    SUM(CASE WHEN action_type = 'creation' THEN 1 ELSE 0 END) as created,
                    SUM(CASE WHEN action_type = 'modification' THEN 1 ELSE 0 END) as modified,
                    SUM(CASE WHEN action_type = 'elimination' THEN 1 ELSE 0 END) as deleted
                FROM archives 
                WHERE {query_conditions} AND created_at >= %s AND created_at <= %s + INTERVAL 1 DAY
                GROUP BY DATE(created_at)
                ORDER BY DATE(created_at) ASC
            """
            cursor.execute(chart_query, tuple(params) + tuple(cfp) + (start_date, end_date))
            daily_stats = cursor.fetchall()
            
            chart_data = {'labels': [], 'created': [], 'modified': [], 'deleted': []}
            stats_map = {row['date']: row for row in daily_stats}
            
            current_date = start_date.date()
            end_date_date = end_date.date()
            
            while current_date <= end_date_date:
                chart_data['labels'].append(current_date.strftime('%Y-%m-%d'))
                if current_date in stats_map:
                    row = stats_map[current_date]
                    chart_data['created'].append(int(row['created']))
                    chart_data['modified'].append(int(row['modified']))
                    chart_data['deleted'].append(int(row['deleted']))
                else:
                    chart_data['created'].append(0)
                    chart_data['modified'].append(0)
                    chart_data['deleted'].append(0)
                current_date += timedelta(days=1)
    
    mitre_info = []
    tags_info = []
    siem_info = None
    if timeline_data:
        siem_info = timeline_data[0].get('siem')
        latest_tags = timeline_data[0].get('tags')
        if latest_tags:
            if isinstance(latest_tags, str):
                try:
                    latest_tags = json.loads(latest_tags)
                except (json.JSONDecodeError, ValueError):
                    latest_tags = []
            if isinstance(latest_tags, list):
                for key in latest_tags:
                    if isinstance(key, str) and ':' in key:
                        cat, val = key.split(':', 1)
                        tags_info.append({'category': cat, 'value': val})
        latest_mitre = timeline_data[0].get('mitre')
        if latest_mitre:
            if isinstance(latest_mitre, str):
                try:
                    latest_mitre = json.loads(latest_mitre)
                except (json.JSONDecodeError, ValueError):
                    latest_mitre = []
            if isinstance(latest_mitre, list):
                tech_ids = set()
                for key in latest_mitre:
                    parts = key.split(':')
                    tech_ids.add(parts[0])
                    if len(parts) == 2:
                        tech_ids.add(parts[1])
                tech_map = {}
                if tech_ids:
                    fmt = ','.join(['%s'] * len(tech_ids))
                    cursor.execute(f"SELECT technique_id, name, tactic FROM mitre_techniques WHERE technique_id IN ({fmt})", tuple(tech_ids))
                    tech_map = {row['technique_id']: row for row in cursor.fetchall()}
                for key in latest_mitre:
                    parts = key.split(':')
                    tech_id = parts[0]
                    sub_id = parts[1] if len(parts) == 2 else None
                    tech = tech_map.get(tech_id, {})
                    entry = {
                        'technique_id': tech_id,
                        'technique_name': tech.get('name', tech_id),
                        'tactic': tech.get('tactic', ''),
                        'subtechnique_id': sub_id,
                        'subtechnique_name': tech_map.get(sub_id, {}).get('name', sub_id) if sub_id else None
                    }
                    mitre_info.append(entry)

    cursor.close()
    conn.close()

    is_active_search = bool(selected_rule or selected_company or selected_environment or selected_status)
    latest_id = timeline_data[0]['id'] if timeline_data else None
    return render_template('history.html', rules=rules, companies=companies, environments=environments, selected_rule=selected_rule, selected_company=selected_company, selected_environment=selected_environment, selected_status=selected_status, timeline=timeline_data, summary=summary, chart_data=chart_data if is_active_search and timeline_data else None, is_active_search=is_active_search, all_rules_metadata=all_rules_metadata, mitre_info=mitre_info, tags_info=tags_info, siem_info=siem_info, tag_categories=TAG_CATEGORIES, latest_id=latest_id)

@app.route('/history/edit-mitre', methods=['POST'])
@login_required
def history_edit_mitre():
    record_id = request.form.get('record_id')
    mitre_raw = request.form.get('mitre_json', '').strip()
    redirect_url = request.form.get('redirect_url', '/history')

    if not record_id:
        flash('Invalid record.', 'error')
        return redirect(redirect_url)

    mitre_data = None
    if mitre_raw:
        try:
            parsed = json.loads(mitre_raw)
            if parsed:
                mitre_data = json.dumps(parsed)
        except (json.JSONDecodeError, ValueError):
            flash('Invalid MITRE data.', 'error')
            return redirect(redirect_url)

    conn = get_db_connection()
    if not conn:
        flash('Database connection failed.', 'error')
        return redirect(redirect_url)

    cursor = conn.cursor()
    cf, cfp = company_filter()
    try:
        cursor.execute(f"UPDATE archives SET mitre = %s WHERE id = %s AND {cf}", (mitre_data, record_id) + tuple(cfp))
        conn.commit()
        flash('MITRE ATT&CK updated.', 'success')
    except mysql.connector.Error as e:
        app.logger.error("history_edit_mitre DB error: %s", e)
        flash('A database error occurred.', 'error')
    finally:
        cursor.close()
        conn.close()

    return redirect(redirect_url)


@app.route('/history/edit-tags', methods=['POST'])
@login_required
def history_edit_tags():
    record_id = request.form.get('record_id')
    tags_raw = request.form.get('tags_json', '').strip()
    redirect_url = request.form.get('redirect_url', '/history')

    if not record_id:
        flash('Invalid record.', 'error')
        return redirect(redirect_url)

    tags_data = None
    parsed = None
    if tags_raw:
        try:
            parsed = json.loads(tags_raw)
            if parsed:
                tags_data = json.dumps(parsed)
        except (json.JSONDecodeError, ValueError):
            flash('Invalid tag data.', 'error')
            return redirect(redirect_url)

    conn = get_db_connection()
    if not conn:
        flash('Database connection failed.', 'error')
        return redirect(redirect_url)

    cursor = conn.cursor()
    try:
        if isinstance(parsed, list):
            clean = []
            for key in parsed:
                if not isinstance(key, str) or ':' not in key:
                    continue
                cat, val = key.split(':', 1)
                cat = cat.strip()[:50]
                val = val.strip()[:255]
                if not cat or not val or cat not in _TAG_CATEGORY_KEYS:
                    continue
                clean.append(f"{cat}:{val}")
                try:
                    cursor.execute(
                        "INSERT IGNORE INTO tags_pool (category, value) VALUES (%s, %s)",
                        (cat, val)
                    )
                except mysql.connector.Error:
                    pass
            tags_data = json.dumps(clean) if clean else None
        cf, cfp = company_filter()
        cursor.execute(f"UPDATE archives SET tags = %s WHERE id = %s AND {cf}", (tags_data, record_id) + tuple(cfp))
        conn.commit()
        flash('Tags updated.', 'success')
    except mysql.connector.Error as e:
        app.logger.error("history_edit_tags DB error: %s", e)
        flash('A database error occurred.', 'error')
    finally:
        cursor.close()
        conn.close()

    return redirect(redirect_url)

@app.route('/diff')
@login_required
def diff_rules():
    selected_rule = request.args.get('rule_name')
    v1_id = request.args.get('v1')
    v2_id = request.args.get('v2')
    
    conn = get_db_connection()
    if not conn:
        flash('Database connection failed.', 'error')
        return redirect(url_for('history'))
        
    cursor = conn.cursor(dictionary=True)
    cf, cfp = company_filter()

    cursor.execute(f"SELECT rule_name FROM archives WHERE {cf} GROUP BY rule_name HAVING COUNT(*) >= 2 ORDER BY rule_name", tuple(cfp))
    all_rules = [row['rule_name'] for row in cursor.fetchall()]

    versions = []
    rule1_data = None
    rule2_data = None

    if selected_rule:
        cursor.execute(f"SELECT id, created_at, action_type, modified_by, tuning_driver FROM archives WHERE rule_name = %s AND {cf} ORDER BY created_at ASC", (selected_rule,) + tuple(cfp))
        rows = cursor.fetchall()
        for i, v in enumerate(rows):
            v['version'] = i + 1
        versions = list(reversed(rows))

        if v1_id:
            cursor.execute(f"SELECT rule_content, created_at FROM archives WHERE id = %s AND {cf}", (v1_id,) + tuple(cfp))
            rule1_data = cursor.fetchone()

        if v2_id:
            cursor.execute(f"SELECT rule_content, created_at FROM archives WHERE id = %s AND {cf}", (v2_id,) + tuple(cfp))
            rule2_data = cursor.fetchone()
            
    cursor.close()
    conn.close()
    
    r1_content = rule1_data['rule_content'] if rule1_data and rule1_data['rule_content'] else ''
    r2_content = rule2_data['rule_content'] if rule2_data and rule2_data['rule_content'] else ''
    
    v1_label = f"Version {rule1_data['created_at'].strftime('%Y-%m-%d %H:%M')}" if rule1_data else "Version 1"
    v2_label = f"Version {rule2_data['created_at'].strftime('%Y-%m-%d %H:%M')}" if rule2_data else "Version 2"
    
    return render_template('diff.html', all_rules=all_rules, selected_rule=selected_rule, versions=versions, v1_id=v1_id, v2_id=v2_id, rule1_content=r1_content, rule2_content=r2_content, v1_label=v1_label, v2_label=v2_label)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        conn = get_db_connection()
        user = None
        if conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()

        if user and check_password_hash(user['password_hash'], password):
            if not user.get('is_active', 1):
                _log_api_audit(user['id'], None, None, 'login_failed',
                               extra_params={'reason': 'account_disabled', 'username': username})
                flash('Account is disabled.', 'error')
                return render_template('login.html')
            if user.get('role') == 'service':
                _log_api_audit(user['id'], None, None, 'login_failed',
                               extra_params={'reason': 'service_account', 'username': username})
                flash('Service accounts cannot log in via web.', 'error')
                return render_template('login.html')
            if user.get('role') == 'third_party':
                _log_api_audit(user['id'], None, None, 'login_failed',
                               extra_params={'reason': 'third_party_account', 'username': username})
                flash('Third-party accounts cannot log in.', 'error')
                return render_template('login.html')
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            _log_api_audit(user['id'], None, None, 'login_success',
                           extra_params={'username': username})
            return redirect(url_for('home'))

        _log_api_audit(user['id'] if user else None, None, None, 'login_failed',
                       extra_params={'username': username})
        flash('Invalid username or password.', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    if request.method == 'POST':
        rule_name = request.form.get('rule_name')
        company_id_in = request.form.get('company_id')
        # When a company is selected globally, that selection governs the record:
        # the form hides the company field, so ignore any submitted value and use
        # the active one (still validated below against the allowed companies).
        active_company = session.get('active_company', 'all')
        if active_company != 'all':
            company_id_in = active_company
        third_party_user = (request.form.get('third_party_user') or '').strip() or None
        siem = request.form.get('siem') or None
        environment = request.form.get('environment')
        action_type = request.form.get('action_type')
        rule_status = request.form.get('rule_status', 'active')
        tuning_driver = request.form.get('tuning_driver', 'maintenance')
        severity = request.form.get('severity') or None
        if severity and severity not in ('critical', 'high', 'medium', 'low', 'informative'):
            severity = None
        ticket = request.form.get('ticket')
        description = request.form.get('description')
        rule_content = request.form.get('rule_content')

        if not rule_name or not environment or not action_type or not severity or not description or not rule_content:
            flash('All mandatory fields must be filled.', 'error')
            return redirect(url_for('register'))

        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)

            allowed = allowed_company_ids()
            cursor.execute("SELECT id, name FROM companies WHERE id = %s AND is_active = 1", (company_id_in,))
            crow = cursor.fetchone()
            if not crow or (allowed is not None and crow['id'] not in allowed):
                cursor.close()
                conn.close()
                flash('Invalid or unauthorized company.', 'error')
                return redirect(url_for('register'))
            company = crow['name']
            company_id = crow['id']

            try:
                cursor.execute("SELECT full_name, username FROM users WHERE id = %s", (session['user_id'],))
                user_info = cursor.fetchone()
                modifier_name = user_info['full_name'] if user_info and user_info.get('full_name') else session.get('username')
            except mysql.connector.Error:
                modifier_name = session.get('username')

            if third_party_user:
                try:
                    cursor.execute("SELECT username, full_name FROM users WHERE username = %s", (third_party_user,))
                    tp = cursor.fetchone()
                    if tp:
                        modifier_name = tp['full_name'] or tp['username']
                except mysql.connector.Error:
                    pass

            mitre_raw = request.form.get('mitre_json', '').strip()
            mitre_data = None
            if mitre_raw:
                try:
                    parsed = json.loads(mitre_raw)
                    if parsed:
                        mitre_data = json.dumps(parsed)
                except (json.JSONDecodeError, ValueError):
                    pass

            tags_raw = request.form.get('tags_json', '').strip()
            tags_data = None
            if tags_raw:
                try:
                    parsed = json.loads(tags_raw)
                    if isinstance(parsed, list):
                        clean = []
                        for key in parsed:
                            if not isinstance(key, str) or ':' not in key:
                                continue
                            cat, val = key.split(':', 1)
                            cat = cat.strip()[:50]
                            val = val.strip()[:255]
                            if not cat or not val or cat not in _TAG_CATEGORY_KEYS:
                                continue
                            clean.append(f"{cat}:{val}")
                            try:
                                cursor.execute(
                                    "INSERT IGNORE INTO tags_pool (category, value) VALUES (%s, %s)",
                                    (cat, val)
                                )
                            except mysql.connector.Error:
                                pass
                        if clean:
                            tags_data = json.dumps(clean)
                except (json.JSONDecodeError, ValueError):
                    pass

            query = "INSERT INTO archives (rule_name, company, company_id, environment, action_type, rule_status, tuning_driver, severity, ticket, description, rule_content, modified_by, mitre, siem, tags) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            values = (rule_name, company, company_id, environment, action_type, rule_status, tuning_driver, severity, ticket, description, rule_content, modifier_name, mitre_data, siem, tags_data)

            try:
                cursor.execute(query, values)
                conn.commit()
                flash('Log registered successfully!', 'success')
            except mysql.connector.Error as err:
                app.logger.error("register insert DB error: %s", err)
                flash('A database error occurred.', 'error')
            finally:
                cursor.close()
                conn.close()
        else:
            flash('Could not connect to database.', 'error')

        return redirect(url_for('register'))

    companies = visible_companies()
    active = session.get('active_company', 'all')
    company_locked = active != 'all' and any(str(c['id']) == active for c in companies)
    default_company_id = None
    if company_locked:
        default_company_id = int(active)
    else:
        default_company_id = next((c['id'] for c in companies if c['name'] == 'Aconetwork'), None)
        if default_company_id is None and companies:
            default_company_id = companies[0]['id']

    conn = get_db_connection()
    rules = []
    users_list = []
    if conn:
        cursor = conn.cursor(dictionary=True)
        cf, cfp = company_filter()
        cursor.execute(f"SELECT DISTINCT rule_name FROM archives WHERE {cf} ORDER BY rule_name", tuple(cfp))
        rules = [r['rule_name'] for r in cursor.fetchall()]
        cursor.execute(
            "SELECT username, COALESCE(NULLIF(full_name,''), username) AS display_name "
            "FROM users WHERE id != %s AND LOWER(role) = 'third_party' ORDER BY display_name",
            (session['user_id'],)
        )
        users_list = cursor.fetchall()
        cursor.close()
        conn.close()
    return render_template('register.html', rules=rules, users=users_list,
                           companies=companies, default_company_id=default_company_id,
                           company_locked=company_locked)


@app.route('/severity-calc')
@login_required
def severity_calc():
    return render_template('severity_calc.html')


TACTIC_ORDER = [
    'reconnaissance', 'resource-development', 'initial-access', 'execution',
    'persistence', 'privilege-escalation', 'defense-impairment', 'stealth',
    'credential-access', 'discovery', 'lateral-movement', 'collection',
    'command-and-control', 'exfiltration', 'impact'
]
TACTIC_LABELS = {
    'reconnaissance': 'Reconnaissance', 'resource-development': 'Resource Development',
    'initial-access': 'Initial Access', 'execution': 'Execution',
    'persistence': 'Persistence', 'privilege-escalation': 'Privilege Escalation',
    'defense-impairment': 'Defense Impairment', 'stealth': 'Stealth',
    'credential-access': 'Credential Access', 'discovery': 'Discovery',
    'lateral-movement': 'Lateral Movement', 'collection': 'Collection',
    'command-and-control': 'Command & Control', 'exfiltration': 'Exfiltration',
    'impact': 'Impact'
}

ICS_TACTIC_ORDER = [
    'initial-access', 'execution', 'persistence', 'privilege-escalation',
    'evasion', 'discovery', 'lateral-movement', 'collection',
    'command-and-control', 'inhibit-response-function',
    'impair-process-control', 'impact'
]
ICS_TACTIC_LABELS = {
    'initial-access': 'Initial Access', 'execution': 'Execution',
    'persistence': 'Persistence', 'privilege-escalation': 'Privilege Escalation',
    'evasion': 'Evasion', 'discovery': 'Discovery',
    'lateral-movement': 'Lateral Movement', 'collection': 'Collection',
    'command-and-control': 'Command & Control',
    'inhibit-response-function': 'Inhibit Response Function',
    'impair-process-control': 'Impair Process Control', 'impact': 'Impact'
}
MITRE_TACTICS = {
    'enterprise': (TACTIC_ORDER, TACTIC_LABELS),
    'ics': (ICS_TACTIC_ORDER, ICS_TACTIC_LABELS),
}

@app.route('/mitre-coverage')
@login_required
def mitre_coverage():
    conn = get_db_connection()
    if not conn:
        flash('Database connection failed.', 'error')
        return redirect(url_for('home'))

    selected_company = request.args.get('company', '').strip()
    selected_domain = request.args.get('domain', 'enterprise').strip()
    if selected_domain not in MITRE_DOMAINS:
        selected_domain = 'enterprise'
    tactic_order, tactic_labels = MITRE_TACTICS[selected_domain]

    cursor = conn.cursor(dictionary=True)
    cf_a, cfp_a = company_filter('a')

    companies = [c['name'] for c in visible_companies()]

    if selected_company:
        cursor.execute(f"""
            SELECT
                mt.technique_id, mt.name, mt.tactic, mt.parent_id,
                COUNT(DISTINCT la.rule_name) as cdu_count
            FROM mitre_techniques mt
            LEFT JOIN (
                SELECT a.rule_name, a.mitre
                FROM archives a
                INNER JOIN (SELECT rule_name, MAX(id) as max_id FROM archives GROUP BY rule_name) latest
                    ON a.id = latest.max_id
                WHERE a.mitre IS NOT NULL AND a.mitre != 'null' AND a.mitre != '[]'
                  AND a.company = %s AND {cf_a}
            ) la ON JSON_CONTAINS(la.mitre, JSON_QUOTE(
                CASE
                    WHEN mt.parent_id IS NOT NULL
                    THEN CONCAT(mt.parent_id, ':', mt.technique_id)
                    ELSE mt.technique_id
                END
            ))
            WHERE mt.domain = %s
            GROUP BY mt.technique_id, mt.name, mt.tactic, mt.parent_id
            ORDER BY mt.technique_id
        """, (selected_company,) + tuple(cfp_a) + (selected_domain,))
    else:
        cursor.execute(f"""
            SELECT
                mt.technique_id, mt.name, mt.tactic, mt.parent_id,
                COUNT(DISTINCT la.rule_name) as cdu_count
            FROM mitre_techniques mt
            LEFT JOIN (
                SELECT a.rule_name, a.mitre
                FROM archives a
                INNER JOIN (SELECT rule_name, MAX(id) as max_id FROM archives GROUP BY rule_name) latest
                    ON a.id = latest.max_id
                WHERE a.mitre IS NOT NULL AND a.mitre != 'null' AND a.mitre != '[]'
                  AND {cf_a}
            ) la ON JSON_CONTAINS(la.mitre, JSON_QUOTE(
                CASE
                    WHEN mt.parent_id IS NOT NULL
                    THEN CONCAT(mt.parent_id, ':', mt.technique_id)
                    ELSE mt.technique_id
                END
            ))
            WHERE mt.domain = %s
            GROUP BY mt.technique_id, mt.name, mt.tactic, mt.parent_id
            ORDER BY mt.technique_id
        """, tuple(cfp_a) + (selected_domain,))
    rows = cursor.fetchall()

    cursor.execute("SELECT last_updated FROM mitre_sync WHERE domain = %s ORDER BY id DESC LIMIT 1", (selected_domain,))
    sync_row = cursor.fetchone()
    last_sync = sync_row['last_updated'].strftime('%Y-%m-%d %H:%M') if sync_row else 'Never'

    cursor.close()
    conn.close()

    techniques_by_id = {}
    subtechniques = []

    for row in rows:
        entry = {
            'id': row['technique_id'],
            'name': row['name'],
            'tactic': row['tactic'] or '',
            'parent_id': row['parent_id'],
            'cdu_count': int(row['cdu_count'] or 0),
            'subtechniques': []
        }
        if row['parent_id']:
            subtechniques.append(entry)
        else:
            techniques_by_id[row['technique_id']] = entry

    for sub in subtechniques:
        parent = techniques_by_id.get(sub['parent_id'])
        if parent:
            parent['subtechniques'].append(sub)

    matrix = {t: {'label': tactic_labels.get(t, t.replace('-', ' ').title()), 'techniques': []} for t in tactic_order}

    for tech in techniques_by_id.values():
        for tactic in [t.strip() for t in tech['tactic'].split(',') if t.strip()]:
            if tactic in matrix:
                matrix[tactic]['techniques'].append(tech)

    for col in matrix.values():
        col['techniques'].sort(key=lambda t: t['id'])
        for tech in col['techniques']:
            tech['subtechniques'].sort(key=lambda s: s['id'])

    total_techniques = len(techniques_by_id)
    covered_techniques = sum(1 for t in techniques_by_id.values() if t['cdu_count'] > 0)
    total_subtechniques = len(subtechniques)
    covered_subtechniques = sum(1 for s in subtechniques if s['cdu_count'] > 0)

    attack_version = get_mitre_domain_config(load_mitre_config(), selected_domain).get('attack_version')
    domain_options = [{'key': k, 'label': v['label']} for k, v in MITRE_DOMAINS.items()]

    return render_template('mitre_coverage.html',
        matrix=matrix, tactic_order=tactic_order,
        total_techniques=total_techniques, covered_techniques=covered_techniques,
        total_subtechniques=total_subtechniques, covered_subtechniques=covered_subtechniques,
        last_sync=last_sync, companies=companies, selected_company=selected_company,
        attack_version=attack_version, domain_options=domain_options,
        selected_domain=selected_domain)

@app.route('/api/mitre/techniques')
@login_required
def api_mitre_techniques():
    conn = get_db_connection()
    if not conn:
        return jsonify([])
    domain = request.args.get('domain', 'enterprise').strip()
    if domain not in MITRE_DOMAINS:
        domain = 'enterprise'
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT technique_id, name, tactic FROM mitre_techniques "
        "WHERE parent_id IS NULL AND domain = %s ORDER BY technique_id",
        (domain,)
    )
    techniques = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(techniques)


@app.route('/api/mitre/subtechniques/<technique_id>')
@login_required
def api_mitre_subtechniques(technique_id):
    conn = get_db_connection()
    if not conn:
        return jsonify([])
    domain = request.args.get('domain', 'enterprise').strip()
    if domain not in MITRE_DOMAINS:
        domain = 'enterprise'
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT technique_id, name FROM mitre_techniques "
        "WHERE parent_id = %s AND domain = %s ORDER BY technique_id",
        (technique_id, domain)
    )
    subs = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(subs)


@app.route('/api/rule/latest')
@login_required
def api_rule_latest():
    rule_name = request.args.get('rule_name', '').strip()
    if not rule_name:
        return jsonify({})
    conn = get_db_connection()
    if not conn:
        return jsonify({})
    cursor = conn.cursor(dictionary=True)
    cf, cfp = company_filter()
    cursor.execute(
        f"SELECT company, siem, environment, severity, rule_status FROM archives WHERE rule_name = %s AND {cf} ORDER BY created_at DESC LIMIT 1",
        (rule_name,) + tuple(cfp)
    )
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    return jsonify(row or {})


@app.route('/api/rule/mitre')
@login_required
def api_rule_mitre():
    rule_name = request.args.get('rule_name', '').strip()
    if not rule_name:
        return jsonify(None)
    conn = get_db_connection()
    if not conn:
        return jsonify(None)
    cursor = conn.cursor(dictionary=True)
    cf, cfp = company_filter()
    cursor.execute(
        f"SELECT mitre FROM archives WHERE rule_name = %s AND {cf} ORDER BY created_at DESC LIMIT 1",
        (rule_name,) + tuple(cfp)
    )
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    if not row or not row['mitre']:
        return jsonify(None)
    mitre = row['mitre']
    if isinstance(mitre, str):
        try:
            mitre = json.loads(mitre)
        except (json.JSONDecodeError, ValueError):
            return jsonify(None)
    return jsonify(mitre)


TAG_CATEGORIES = [
    {'key': 'baseline',           'label': 'Baseline'},
    {'key': 'hardware_family',    'label': 'Hardware Family'},
    {'key': 'os_family',          'label': 'OS Family'},
    {'key': 'network_family',     'label': 'Network Family'},
    {'key': 'application_family', 'label': 'Application Family'},
    {'key': 'vendor',             'label': 'Vendor'},
    {'key': 'criticality',        'label': 'Criticality'},
]
_TAG_CATEGORY_KEYS = {c['key'] for c in TAG_CATEGORIES}


@app.route('/api/tags/categories')
@login_required
def api_tag_categories():
    return jsonify(TAG_CATEGORIES)


@app.route('/api/tags', methods=['GET', 'POST'])
@login_required
def api_tags():
    if request.method == 'GET':
        category = request.args.get('category', '').strip()
        if not category:
            return jsonify([])
        conn = get_db_connection()
        if not conn:
            return jsonify([])
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT value FROM tags_pool WHERE category = %s ORDER BY value",
            (category,)
        )
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify([r['value'] for r in rows])

    payload = request.get_json(silent=True) or {}
    category = (payload.get('category') or '').strip()
    value = (payload.get('value') or '').strip()
    if not category or not value:
        return jsonify({'error': 'category and value required'}), 400
    if category not in _TAG_CATEGORY_KEYS:
        return jsonify({'error': 'invalid category'}), 400
    if len(value) > 255:
        return jsonify({'error': 'value too long'}), 400
    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'db unavailable'}), 503
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT IGNORE INTO tags_pool (category, value) VALUES (%s, %s)",
            (category, value)
        )
        conn.commit()
    finally:
        cursor.close()
        conn.close()
    return jsonify({'category': category, 'value': value})


@app.route('/api/rule/tags')
@login_required
def api_rule_tags():
    rule_name = request.args.get('rule_name', '').strip()
    if not rule_name:
        return jsonify(None)
    conn = get_db_connection()
    if not conn:
        return jsonify(None)
    cursor = conn.cursor(dictionary=True)
    cf, cfp = company_filter()
    cursor.execute(
        f"SELECT tags FROM archives WHERE rule_name = %s AND {cf} ORDER BY created_at DESC LIMIT 1",
        (rule_name,) + tuple(cfp)
    )
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    if not row or not row['tags']:
        return jsonify(None)
    tags = row['tags']
    if isinstance(tags, str):
        try:
            tags = json.loads(tags)
        except (json.JSONDecodeError, ValueError):
            return jsonify(None)
    return jsonify(tags)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    conn = get_db_connection()
    if not conn:
        flash('Database connection failed.', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'update_info':
            full_name = request.form.get('full_name')
            file = request.files.get('profile_pic')
            
            cursor = None
            try:
                cursor = conn.cursor()
                
                cursor.execute("UPDATE users SET full_name = %s WHERE id = %s", (full_name, session['user_id']))
                
                if file and file.filename != '' and allowed_file(file.filename):
                    file.seek(0, 2)
                    file_size = file.tell()
                    file.seek(0)
                    if file_size > 5 * 1024 * 1024:
                        flash('Profile picture must be under 5MB.', 'error')
                    else:
                        filename = secure_filename(f"user_{session['user_id']}_{file.filename}")
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                        cursor.execute("UPDATE users SET profile_pic = %s WHERE id = %s", (filename, session['user_id']))
                
                conn.commit()
                flash('Profile updated successfully!', 'success')
            except mysql.connector.Error as err:
                app.logger.error("profile update_info DB error: %s", err)
                flash('Could not update profile.', 'error')
            finally:
                if cursor:
                    cursor.close()

        elif action == 'change_password':
            current_password = request.form.get('current_password')
            new_password = request.form.get('new_password')
            confirm_password = request.form.get('confirm_password')
            
            if not current_password or not new_password or not confirm_password:
                flash('All password fields are required.', 'error')
            elif new_password != confirm_password:
                flash('New passwords do not match.', 'error')
            else:
                cursor = None
                try:
                    cursor = conn.cursor(dictionary=True)
                    cursor.execute("SELECT password_hash FROM users WHERE id = %s", (session['user_id'],))
                    user = cursor.fetchone()
                    
                    if user and check_password_hash(user['password_hash'], current_password):
                        new_hash = generate_password_hash(new_password)
                        cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, session['user_id']))
                        conn.commit()
                        flash('Password updated successfully!', 'success')
                    else:
                        flash('Incorrect current password.', 'error')
                except mysql.connector.Error as err:
                    app.logger.error("profile change_password DB error: %s", err)
                    flash('A database error occurred.', 'error')
                finally:
                    if cursor:
                        cursor.close()

        elif action == 'update_theme':
            theme = request.form.get('theme')
            if theme in ['dark', 'light']:
                cursor = None
                try:
                    cursor = conn.cursor()
                    cursor.execute("UPDATE users SET theme_preference = %s WHERE id = %s", (theme, session['user_id']))
                    conn.commit()
                    flash(f'Theme updated to {theme.title()} Mode.', 'success')
                except mysql.connector.Error as err:
                    app.logger.error("profile update_theme DB error: %s", err)
                    flash('Could not update theme.', 'error')
                finally:
                    if cursor:
                        cursor.close()
            else:
                flash('Invalid theme selected.', 'error')

        conn.close()
        return redirect(url_for('profile'))

    cursor = None
    user_data = None
    try:
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT username, full_name, role, profile_pic, theme_preference FROM users WHERE id = %s", (session['user_id'],))
        except mysql.connector.Error:
            cursor.execute("SELECT username, role, profile_pic, theme_preference FROM users WHERE id = %s", (session['user_id'],))
        user_data = cursor.fetchone()
    finally:
        if cursor:
            cursor.close()
        conn.close()

    return render_template('profile.html', user=user_data)

@app.route('/health')
def health():
    return "OK", 200

class _HealthAccessFilter(logging.Filter):
    def filter(self, record):
        return '/health ' not in record.getMessage()

class _TLSHandshakeFilter(logging.Filter):
    # Browsers rejecting the self-signed cert send a TLS alert; gunicorn logs it
    # as an "Invalid request" warning. Drop only that noise, keep real ones.
    def filter(self, record):
        return 'ssl/tls alert' not in record.getMessage().lower()

logging.getLogger('gunicorn.access').addFilter(_HealthAccessFilter())
logging.getLogger('gunicorn.error').addFilter(_TLSHandshakeFilter())

# Route app.logger through gunicorn's handlers so leveled logs reach stdout/stderr
# (where the log collector reads). Falls back to basic config for local `python`.
_gunicorn_error_logger = logging.getLogger('gunicorn.error')
if _gunicorn_error_logger.handlers:
    app.logger.handlers = _gunicorn_error_logger.handlers
    app.logger.setLevel(_gunicorn_error_logger.level)
else:
    logging.basicConfig(level=logging.INFO)
    app.logger.setLevel(logging.INFO)

try:
    with app.app_context():
        init_db()
        startup_mitre_check()
except Exception as e:
    app.logger.warning("Could not initialize on startup: %s", e)

def admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))

        user = _current_user()
        if not user or user.get('role') not in ('admin', 'superadmin'):
            flash('Admin privileges required.', 'error')
            return redirect(url_for('home'))

        return view(**kwargs)
    return wrapped_view

def superadmin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))

        user = _current_user()
        if not user or user.get('role') != 'superadmin':
            flash('Superadmin privileges required.', 'error')
            return redirect(url_for('home'))

        return view(**kwargs)
    return wrapped_view

@app.route('/users')
@login_required
@admin_required
def users():
    conn = get_db_connection()
    if not conn:
        flash('Database connection failed.', 'error')
        return redirect(url_for('home'))
    
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT u.id, u.username, u.full_name, u.role, u.profile_pic,
               COALESCE(u.is_active, 1) as is_active,
               COALESCE(u.is_protected, 0) as is_protected
        FROM users u
        ORDER BY u.username
    """)
    users_data = cursor.fetchall()

    cursor.execute("SELECT id, name FROM companies WHERE is_active = 1 ORDER BY name")
    all_companies = cursor.fetchall()
    cursor.execute("SELECT user_id, company_id FROM user_companies")
    assignments = {}
    for r in cursor.fetchall():
        assignments.setdefault(r['user_id'], set()).add(r['company_id'])
    for u in users_data:
        u['company_ids'] = assignments.get(u['id'], set())

    cursor.close()
    conn.close()

    return render_template('users.html', users=users_data, all_companies=all_companies)

@app.route('/users/add', methods=['POST'])
@login_required
@admin_required
def add_user():
    username = request.form.get('username')
    full_name = request.form.get('full_name')
    password = request.form.get('password')
    role = request.form.get('role')

    if not username or not role:
        flash('Username and role are required.', 'error')
        return redirect(url_for('users'))

    if role != 'third_party' and not password:
        flash('Password is required for this role.', 'error')
        return redirect(url_for('users'))

    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            if role == 'third_party':
                hashed_password = generate_password_hash(secrets.token_hex(32))
            else:
                hashed_password = generate_password_hash(password)
            cursor.execute("INSERT INTO users (username, full_name, password_hash, role) VALUES (%s, %s, %s, %s)",
                        (username, full_name, hashed_password, role))
            new_user_id = cursor.lastrowid
            company_ids = request.form.getlist('company_ids')
            assign = []
            for cid in company_ids:
                try:
                    assign.append((new_user_id, int(cid)))
                except (ValueError, TypeError):
                    pass
            if assign:
                cursor.executemany(
                    "INSERT IGNORE INTO user_companies (user_id, company_id) VALUES (%s, %s)",
                    assign
                )
            conn.commit()
            flash('User created successfully.', 'success')
        except mysql.connector.Error as err:
            app.logger.error("add_user DB error: %s", err)
            flash('Could not create user (the username may already exist).', 'error')
        finally:
            cursor.close()
            conn.close()
            
    return redirect(url_for('users'))

@app.route('/users/edit/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def edit_user(user_id):
    action = request.form.get('action')
    
    conn = get_db_connection()
    if not conn:
        return redirect(url_for('users'))
        
    cursor = conn.cursor()
    
    try:
        if action == 'update_role':
            new_role = request.form.get('role')
            cursor.execute("UPDATE users SET role = %s WHERE id = %s", (new_role, user_id))
            flash('User role updated.', 'success')

        elif action == 'reset_password':
            new_password = request.form.get('password')
            if new_password:
                new_hash = generate_password_hash(new_password)
                cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (new_hash, user_id))
                flash('User password reset.', 'success')
            else:
                flash('Password cannot be empty.', 'error')

        elif action in ('enable', 'disable'):
            val = 1 if action == 'enable' else 0
            cursor.execute("UPDATE users SET is_active = %s WHERE id = %s", (val, user_id))
            flash(f'User {"enabled" if val else "disabled"}.', 'success')
                
        conn.commit()
    except mysql.connector.Error as err:
        app.logger.error("edit_user DB error: %s", err)
        flash('Could not update user.', 'error')
    finally:
        cursor.close()
        conn.close()
        
    return redirect(url_for('users'))

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    if user_id == session['user_id']:
        flash('You cannot delete yourself.', 'error')
        return redirect(url_for('users'))
        
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT is_protected FROM users WHERE id = %s", (user_id,))
            row = cursor.fetchone()
            if row and row[0]:
                flash('This account is protected and cannot be deleted.', 'error')
                return redirect(url_for('users'))
            cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
            conn.commit()
            flash('User deleted successfully.', 'success')
        except mysql.connector.Error as err:
            app.logger.error("delete_user DB error: %s", err)
            flash('Could not delete user.', 'error')
        finally:
            cursor.close()
            conn.close()
            
    return redirect(url_for('users'))


@app.route('/companies')
@login_required
@admin_required
def companies():
    conn = get_db_connection()
    if not conn:
        flash('Database connection failed.', 'error')
        return redirect(url_for('home'))
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT c.id, c.name, c.is_active,
               (SELECT COUNT(*) FROM archives a WHERE a.company_id = c.id) AS archive_count,
               (SELECT COUNT(*) FROM user_companies uc WHERE uc.company_id = c.id) AS user_count
        FROM companies c
        ORDER BY c.name
    """)
    companies_data = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('companies.html', companies=companies_data)


@app.route('/companies/add', methods=['POST'])
@login_required
@admin_required
def add_company():
    name = (request.form.get('name') or '').strip()
    if not name:
        flash('Company name is required.', 'error')
        return redirect(url_for('companies'))
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO companies (name) VALUES (%s)", (name,))
            conn.commit()
            _log_api_audit(session['user_id'], None, None, 'company_created', {'name': name})
            flash('Company created.', 'success')
        except mysql.connector.Error as err:
            app.logger.error("add_company DB error: %s", err)
            flash('Could not create company (the name may already exist).', 'error')
        finally:
            cursor.close()
            conn.close()
    return redirect(url_for('companies'))


@app.route('/companies/edit/<int:company_id>', methods=['POST'])
@login_required
@admin_required
def edit_company(company_id):
    name = (request.form.get('name') or '').strip()
    is_active = 1 if request.form.get('is_active') == '1' else 0
    if not name:
        flash('Company name is required.', 'error')
        return redirect(url_for('companies'))
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("UPDATE companies SET name = %s, is_active = %s WHERE id = %s", (name, is_active, company_id))
            conn.commit()
            flash('Company updated.', 'success')
        except mysql.connector.Error as err:
            app.logger.error("edit_company DB error: %s", err)
            flash('Could not update company (the name may already exist).', 'error')
        finally:
            cursor.close()
            conn.close()
    return redirect(url_for('companies'))


@app.route('/companies/delete/<int:company_id>', methods=['POST'])
@login_required
@admin_required
def delete_company(company_id):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT COUNT(*) FROM archives WHERE company_id = %s", (company_id,))
            has_archives = cursor.fetchone()[0] > 0
            if has_archives:
                cursor.execute("UPDATE companies SET is_active = 0 WHERE id = %s", (company_id,))
                flash('Company has archives; deactivated instead of deleted.', 'success')
            else:
                cursor.execute("DELETE FROM companies WHERE id = %s", (company_id,))
                flash('Company deleted.', 'success')
            conn.commit()
        except mysql.connector.Error as err:
            app.logger.error("delete_company DB error: %s", err)
            flash('Could not delete company.', 'error')
        finally:
            cursor.close()
            conn.close()
    return redirect(url_for('companies'))


@app.route('/users/<int:user_id>/companies', methods=['POST'])
@login_required
@admin_required
def set_user_companies(user_id):
    company_ids = request.form.getlist('company_ids')
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            cursor.execute("DELETE FROM user_companies WHERE user_id = %s", (user_id,))
            assign = []
            for cid in company_ids:
                try:
                    assign.append((user_id, int(cid)))
                except (ValueError, TypeError):
                    pass
            if assign:
                cursor.executemany(
                    "INSERT IGNORE INTO user_companies (user_id, company_id) VALUES (%s, %s)",
                    assign
                )
            conn.commit()
            _log_api_audit(session['user_id'], None, None, 'company_assigned',
                           {'user_id': user_id, 'companies': [a[1] for a in assign]})
            flash('Company assignments updated.', 'success')
        except mysql.connector.Error as err:
            app.logger.error("set_user_companies DB error: %s", err)
            flash('Could not update company assignments.', 'error')
        finally:
            cursor.close()
            conn.close()
    return redirect(url_for('users'))


BACKUP_FOLDER = os.path.join(BASE_DIR, 'backups')
if not os.path.exists(BACKUP_FOLDER):
    os.makedirs(BACKUP_FOLDER)

def generate_backup_custom(filepath):
    conn = get_db_connection()
    if not conn:
        return False

    tmp_path = filepath + '.tmp'
    try:
        cursor = conn.cursor()
        with open(tmp_path, 'w', encoding='utf-8') as f:
            f.write(f"-- Chronomancers Archives Backup\n")
            f.write(f"-- Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            cursor.execute("SHOW TABLES")
            tables = [table[0] for table in cursor.fetchall()]

            for table_name in tables:
                cursor.execute(f"SHOW CREATE TABLE {table_name}")
                create_table_sql = cursor.fetchone()[1]
                f.write(f"DROP TABLE IF EXISTS `{table_name}`;\n")
                f.write(f"{create_table_sql};\n\n")

                cursor.execute(f"SELECT * FROM {table_name}")
                rows = cursor.fetchall()
                if rows:
                    f.write(f"INSERT INTO `{table_name}` VALUES \n")
                    values_list = []
                    for row in rows:
                        row_values = []
                        for val in row:
                            if val is None:
                                row_values.append("NULL")
                            elif isinstance(val, (int, float)):
                                row_values.append(str(val))
                            else:
                                escaped_val = str(val).replace("\\", "\\\\").replace("'", "\\'")
                                row_values.append(f"'{escaped_val}'")
                        values_list.append(f"({', '.join(row_values)})")
                    f.write(",\n".join(values_list))
                    f.write(";\n\n")

        cursor.close()
        conn.close()
        os.replace(tmp_path, filepath)
        return True
    except Exception as e:
        app.logger.error("Backup error: %s", e)
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        return False

def _split_sql_statements(sql):
    statements = []
    current = []
    in_string = False
    string_char = None
    i = 0
    while i < len(sql):
        c = sql[i]
        if in_string:
            if c == '\\':
                current.append(c)
                i += 1
                if i < len(sql):
                    current.append(sql[i])
                    i += 1
                continue
            elif c == string_char:
                in_string = False
        else:
            if c in ("'", '"', '`'):
                in_string = True
                string_char = c
            elif c == ';':
                stmt = ''.join(current).strip()
                if stmt:
                    statements.append(stmt)
                current = []
                i += 1
                continue
        current.append(c)
        i += 1
    stmt = ''.join(current).strip()
    if stmt:
        statements.append(stmt)
    return statements

def restore_backup_custom(filepath):
    conn = get_db_connection()
    if not conn:
        return False

    cursor = conn.cursor()
    try:
        cursor.execute("SET FOREIGN_KEY_CHECKS = 0")

        with open(filepath, 'r', encoding='utf-8') as f:
            sql_script = f.read()

        for statement in _split_sql_statements(sql_script):
            cursor.execute(statement)

        conn.commit()
        return True
    except Exception as e:
        app.logger.error("Restore error: %s", e)
        return False
    finally:
        try:
            cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
        except mysql.connector.Error:
            pass
        cursor.close()
        conn.close()

@app.route('/admin/mitre')
@login_required
@admin_required
def admin_mitre():
    config = load_mitre_config()
    conn = get_db_connection()
    domains = []
    cursor = conn.cursor(dictionary=True) if conn else None
    for key, meta in MITRE_DOMAINS.items():
        info = {
            'key': key,
            'label': meta['label'],
            'config': get_mitre_domain_config(config, key),
            'techniques': 0,
            'subtechniques': 0,
            'last_sync': None,
        }
        if cursor:
            cursor.execute("SELECT COUNT(*) as cnt FROM mitre_techniques WHERE parent_id IS NULL AND domain = %s", (key,))
            info['techniques'] = cursor.fetchone()['cnt']
            cursor.execute("SELECT COUNT(*) as cnt FROM mitre_techniques WHERE parent_id IS NOT NULL AND domain = %s", (key,))
            info['subtechniques'] = cursor.fetchone()['cnt']
            cursor.execute("SELECT last_updated FROM mitre_sync WHERE domain = %s ORDER BY id DESC LIMIT 1", (key,))
            row = cursor.fetchone()
            if row:
                info['last_sync'] = row['last_updated'].strftime('%Y-%m-%d %H:%M:%S')
        domains.append(info)
    if cursor:
        cursor.close()
        conn.close()
    return render_template('mitre_admin.html', domains=domains)

@app.route('/admin/mitre/sync', methods=['POST'])
@login_required
@admin_required
def admin_mitre_sync():
    domain = request.form.get('domain', 'enterprise').strip()
    if domain not in MITRE_DOMAINS:
        flash('Unknown MITRE domain.', 'error')
        return redirect(url_for('admin_mitre'))
    t = threading.Thread(target=sync_mitre_data, args=(domain,), daemon=True)
    t.start()
    t.join(timeout=180)
    if t.is_alive():
        flash(f'{MITRE_DOMAINS[domain]["label"]} sync started in background - may take a few minutes.', 'info')
    else:
        flash(f'{MITRE_DOMAINS[domain]["label"]} ATT&CK sync completed successfully.', 'success')
    return redirect(url_for('admin_mitre'))

@app.route('/backup', methods=['GET'])
@login_required
@admin_required
def list_backups():
    backups = []
    if os.path.exists(BACKUP_FOLDER):
        for f in os.listdir(BACKUP_FOLDER):
            if f.endswith('.sql'):
                path = os.path.join(BACKUP_FOLDER, f)
                created_time = datetime.fromtimestamp(os.path.getctime(path)).strftime('%Y-%m-%d %H:%M:%S')
                size_mb = os.path.getsize(path) / (1024 * 1024)
                backups.append({
                    'name': f,
                    'size': f"{size_mb:.2f} MB",
                    'date': created_time
                })
    backups.sort(key=lambda x: x['date'], reverse=True)
    return render_template('backup.html', backups=backups)

@app.route('/backup/create', methods=['POST'])
@login_required
@admin_required
def create_backup():
    filename = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sql"
    filepath = os.path.join(BACKUP_FOLDER, filename)
    
    if generate_backup_custom(filepath):
        flash(f"Backup '{filename}' created successfully.", "success")
    else:
        flash("Error creating backup.", "error")
    
    return redirect(url_for('list_backups'))

@app.route('/backup/restore/<filename>', methods=['POST'])
@login_required
@admin_required
def restore_backup(filename):
    filename = secure_filename(filename)
    filepath = os.path.join(BACKUP_FOLDER, filename)
    if not os.path.exists(filepath):
        flash("Archivo de respaldo no encontrado.", "error")
        return redirect(url_for('list_backups'))
    
    if restore_backup_custom(filepath):
        # A backup taken before a schema change restores the old schema; re-run
        # the migrations so newer columns/indexes are present again.
        init_db()
        # The restore overwrites MITRE data with whatever the backup held; a
        # backup may lack a domain (e.g. ICS), leaving it empty. Re-run the
        # startup check so missing/stale domains sync in the background.
        startup_mitre_check()
        # The restore replaces the users table, so the current session may point
        # to a user that no longer exists. Force a re-login without flashing a
        # message that reveals a restore happened.
        session.clear()
        return redirect(url_for('login'))

    flash("Error restoring database.", "error")
    return redirect(url_for('list_backups'))

@app.route('/backup/delete/<filename>', methods=['POST'])
@login_required
@admin_required
def delete_backup(filename):
    filename = secure_filename(filename)
    filepath = os.path.join(BACKUP_FOLDER, filename)
    if os.path.exists(filepath):
        os.remove(filepath)
        flash(f"Backup '{filename}' deleted.", "success")
    else:
        flash("File not found.", "error")
    return redirect(url_for('list_backups'))

@app.route('/backup/download/<filename>')
@login_required
@admin_required
def download_backup(filename):
    filename = secure_filename(filename)
    return send_file(os.path.join(BACKUP_FOLDER, filename), as_attachment=True)

@app.route('/backup/upload', methods=['POST'])
@login_required
@admin_required
def upload_backup():
    if 'backup_file' not in request.files:
        flash('No file part', 'error')
        return redirect(url_for('list_backups'))
    
    file = request.files['backup_file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('list_backups'))
        
    if not (file and file.filename.lower().endswith('.sql')):
        flash('Invalid file format. Only .sql files are allowed.', 'error')
        return redirect(url_for('list_backups'))

    # The restore path executes every statement in this file, so accept only a
    # plausible plain-text SQL dump: reject binary (NUL bytes / non-UTF-8) and
    # require the content to start with a SQL comment or statement.
    file.seek(0, 2)
    size = file.tell()
    file.seek(0)
    if size > MAX_BACKUP_SIZE:
        flash(f'Backup too large (max {MAX_BACKUP_SIZE // (1024 * 1024)} MB).', 'error')
        return redirect(url_for('list_backups'))
    head = file.read(4096)
    file.seek(0)
    if b'\x00' in head:
        flash('Invalid backup: file is not plain-text SQL.', 'error')
        return redirect(url_for('list_backups'))
    # Only the start of the file is inspected; decode tolerantly so a multi-byte
    # character straddling the 4096-byte read boundary does not reject a valid dump.
    head_text = head.decode('utf-8', errors='ignore')
    if not head_text.lstrip().startswith(('--', '/*', 'DROP', 'CREATE', 'INSERT', 'SET', 'USE', 'LOCK')):
        flash('Invalid backup: does not look like a SQL dump.', 'error')
        return redirect(url_for('list_backups'))

    filename = secure_filename(file.filename)
    file.save(os.path.join(BACKUP_FOLDER, filename))
    flash(f'Backup "{filename}" uploaded successfully.', 'success')
    return redirect(url_for('list_backups'))

# --- SCHEDULER CONFIGURATION ---

SCHEDULER_CONFIG_FILE = os.path.join(BASE_DIR, 'backup.conf')
scheduler = None

if scheduler_available:
    try:
        scheduler = BackgroundScheduler()
    except Exception as e:
        app.logger.error("Error initializing scheduler: %s", e)
        scheduler_available = False

# Backup scheduling and backup log rotation are enabled out of the box; a value
# saved to backup.conf overrides the matching default.
DEFAULT_SCHEDULE_CONFIG = {
    'enabled': True,
    'frequency': 'daily',
    'time': '00:00',
    'logrotate_auto': True,
    'logrotate_days': 7,
}

def load_schedule_config():
    config = dict(DEFAULT_SCHEDULE_CONFIG)
    if os.path.exists(SCHEDULER_CONFIG_FILE):
        try:
            with open(SCHEDULER_CONFIG_FILE, 'r') as f:
                config.update(json.load(f))
        except (json.JSONDecodeError, ValueError, TypeError, OSError):
            pass
    return config

def save_schedule_config(config):
    with open(SCHEDULER_CONFIG_FILE, 'w') as f:
        json.dump(config, f)

def scheduled_backup_job():
    with app.app_context():
        filename = f"auto_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sql"
        filepath = os.path.join(BACKUP_FOLDER, filename)
        app.logger.info("Running scheduled backup: %s", filename)
        generate_backup_custom(filepath)
        config = load_schedule_config()
        if config.get('logrotate_auto'):
            days = int(config.get('logrotate_days', 7))
            cutoff = datetime.now() - timedelta(days=days)
            deleted = 0
            if os.path.exists(BACKUP_FOLDER):
                for f in os.listdir(BACKUP_FOLDER):
                    if f.endswith('.sql'):
                        path = os.path.join(BACKUP_FOLDER, f)
                        if datetime.fromtimestamp(os.path.getctime(path)) < cutoff:
                            os.remove(path)
                            deleted += 1
            app.logger.info("Log rotation: %s backup(s) older than %s days removed.", deleted, days)

def init_scheduler():
    if not scheduler_available or not scheduler:
        return

    config = load_schedule_config()
    if config.get('enabled'):
        frequency = config.get('frequency')
        backup_time = config.get('time', '00:00')
        try:
            hour, minute = backup_time.split(':')
            
            trigger = None
            if frequency == 'daily':
                trigger = CronTrigger(hour=hour, minute=minute)
            elif frequency == 'weekly':
                trigger = CronTrigger(day_of_week='mon', hour=hour, minute=minute)
                
            if trigger:
                scheduler.add_job(
                    func=scheduled_backup_job,
                    trigger=trigger,
                    id='backup_job',
                    name='Scheduled Backup',
                    replace_existing=True
                )
                if not scheduler.running:
                    scheduler.start()
        except ValueError:
            app.logger.warning("Invalid time format in schedule config.")
    else:
        if scheduler.get_job('backup_job'):
            scheduler.remove_job('backup_job')

if scheduler_available:
    init_scheduler()
    if scheduler:
        try:
            scheduler.add_job(
                func=sync_all_mitre,
                trigger=IntervalTrigger(days=7),
                id='mitre_sync_job',
                name='MITRE ATT&CK Sync',
                replace_existing=True
            )
            if not scheduler.running:
                scheduler.start()
        except Exception as e:
            app.logger.error("MITRE scheduler error: %s", e)

        def safe_shutdown():
            if scheduler.running:
                scheduler.shutdown()
        atexit.register(safe_shutdown)

@app.route('/backup/logrotate/save', methods=['POST'])
@login_required
@admin_required
def save_logrotate():
    days = request.form.get('logrotate_days', '7')
    try:
        days = max(1, int(days))
    except ValueError:
        days = 7
    auto = request.form.get('logrotate_auto') == 'on'
    config = load_schedule_config()
    config['logrotate_days'] = days
    config['logrotate_auto'] = auto
    save_schedule_config(config)
    flash(f'Log rotation set to {days} days (auto: {"enabled" if auto else "disabled"}).', 'success')
    return redirect(url_for('list_backups'))

@app.route('/backup/logrotate/run', methods=['POST'])
@login_required
@admin_required
def run_logrotate():
    config = load_schedule_config()
    days = int(config.get('logrotate_days', 7))
    cutoff = datetime.now() - timedelta(days=days)
    deleted = 0
    if os.path.exists(BACKUP_FOLDER):
        for f in os.listdir(BACKUP_FOLDER):
            if f.endswith('.sql'):
                path = os.path.join(BACKUP_FOLDER, f)
                if datetime.fromtimestamp(os.path.getctime(path)) < cutoff:
                    os.remove(path)
                    deleted += 1
    flash(f'Log rotation complete: {deleted} backup(s) older than {days} days removed.', 'success')
    return redirect(url_for('list_backups'))

@app.route('/backup/schedule', methods=['POST'])
@login_required
@admin_required
def schedule_backup():
    if not scheduler_available:
        flash('El sistema de programación no está disponible (APScheduler no instalado).', 'error')
        return redirect(url_for('list_backups'))

    enabled = request.form.get('enabled') == 'on'
    frequency = request.form.get('frequency')
    backup_time = request.form.get('time')

    config = load_schedule_config()
    config['enabled'] = enabled
    config['frequency'] = frequency
    config['time'] = backup_time

    save_schedule_config(config)
    init_scheduler()

    flash('Programación de respaldo actualizada.', 'success')
    return redirect(url_for('list_backups'))

@app.context_processor
def inject_schedule_config():
    if request.endpoint == 'list_backups':
        return dict(schedule_config=load_schedule_config())
    return dict()

# --- API KEY & AUDIT ---

def _log_api_audit(user_id, api_key_id, status_code, action='api_call', extra_params=None):
    try:
        conn = get_db_connection()
        if not conn:
            return
        params = dict(request.args)
        if extra_params:
            params.update(extra_params)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO api_audit_log (user_id, api_key_id, action, ip_address, endpoint, params, status_code) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (user_id, api_key_id, action, request.remote_addr, request.path, json.dumps(params), status_code)
        )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception:
        pass


@app.route('/audit')
@login_required
@admin_required
def audit():
    conn = get_db_connection()
    if not conn:
        flash('Database connection failed.', 'error')
        return redirect(url_for('home'))

    try:
        page = max(1, int(request.args.get('page', 1)))
    except ValueError:
        page = 1
    per_page = 50

    f_action   = request.args.get('action', '').strip()
    f_username = request.args.get('username', '').strip()
    f_ip       = request.args.get('ip', '').strip()

    conditions, params = [], []
    if f_action:
        conditions.append("l.action = %s")
        params.append(f_action)
    if f_username:
        conditions.append("u.username LIKE %s")
        params.append(f'%{f_username}%')
    if f_ip:
        conditions.append("l.ip_address LIKE %s")
        params.append(f'%{f_ip}%')

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    cursor = conn.cursor(dictionary=True)
    cursor.execute(f"""
        SELECT COUNT(*) as total
        FROM api_audit_log l
        LEFT JOIN users u ON l.user_id = u.id
        {where}
    """, tuple(params))
    total = cursor.fetchone()['total']

    offset = (page - 1) * per_page
    cursor.execute(f"""
        SELECT l.id, l.action, l.ip_address, l.endpoint, l.params, l.status_code, l.created_at,
               u.username, u.full_name
        FROM api_audit_log l
        LEFT JOIN users u ON l.user_id = u.id
        {where}
        ORDER BY l.created_at DESC
        LIMIT %s OFFSET %s
    """, tuple(params) + (per_page, offset))
    logs = cursor.fetchall()

    cursor.execute("SELECT DISTINCT action FROM api_audit_log ORDER BY action")
    action_choices = [r['action'] for r in cursor.fetchall()]

    cursor.close()
    conn.close()

    pages = max(1, (total + per_page - 1) // per_page)
    return render_template('audit.html', logs=logs, page=page, pages=pages, total=total,
                           f_action=f_action, f_username=f_username, f_ip=f_ip,
                           action_choices=action_choices)


# --- SSL / TLS MANAGEMENT (superadmin) ---

CERT_FILE = os.path.join(CERT_DIR, 'cert.pem')
KEY_FILE = os.path.join(CERT_DIR, 'key.pem')
# Presence marks the cert as web-managed; docker/entrypoint.sh then never
# regenerates it (so an uploaded self-signed cert is not overwritten on restart).
CERT_MANAGED_MARKER = os.path.join(CERT_DIR, '.managed')


def _read_cert_info():
    """Parsed details of the cert on disk, or None when absent/unreadable."""
    if not os.path.exists(CERT_FILE):
        return None
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID, ExtensionOID
        with open(CERT_FILE, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
    except Exception:
        return None

    def _cn(name):
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else ''

    sans = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    return {
        'cn': _cn(cert.subject),
        'issuer': _cn(cert.issuer),
        'sans': sans,
        'not_before': cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S UTC'),
        'not_after': cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S UTC'),
        'expired': cert.not_valid_after_utc < datetime.now(cert.not_valid_after_utc.tzinfo),
        'self_signed': cert.issuer == cert.subject,
        'managed': os.path.exists(CERT_MANAGED_MARKER),
    }


def _validate_cert_pair(cert_bytes, key_bytes):
    """Return (cert, error). cert is the parsed x509 when the PEM pair is valid
    and the private key matches the certificate; otherwise error explains why."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    try:
        cert = x509.load_pem_x509_certificate(cert_bytes)
    except Exception:
        return None, 'The certificate is not a valid PEM certificate.'
    try:
        key = load_pem_private_key(key_bytes, password=None)
    except TypeError:
        return None, 'The private key is encrypted; upload an unencrypted key.'
    except Exception:
        return None, 'The private key is not a valid PEM private key.'

    pub_fmt = serialization.PublicFormat.SubjectPublicKeyInfo
    pem_enc = serialization.Encoding.PEM
    cert_pub = cert.public_key().public_bytes(pem_enc, pub_fmt)
    key_pub = key.public_key().public_bytes(pem_enc, pub_fmt)
    if cert_pub != key_pub:
        return None, 'The private key does not match the certificate.'
    return cert, None


def _reload_tls():
    """Ask the gunicorn master to reload so new workers pick up the cert on disk.
    The worker's parent is the master; SIGHUP rebuilds the SSL context from the
    same cert/key paths. No-op when not running under gunicorn (e.g. dev server)."""
    if not request.environ.get('SERVER_SOFTWARE', '').startswith('gunicorn'):
        return False
    try:
        os.kill(os.getppid(), signal.SIGHUP)
        return True
    except OSError:
        return False


@app.route('/admin/ssl')
@login_required
@superadmin_required
def admin_ssl():
    return render_template(
        'ssl.html',
        cert=_read_cert_info(),
        cert_dir=CERT_DIR,
        ssl_enabled=os.getenv('ENABLE_SSL', 'false').lower() == 'true',
    )


@app.route('/admin/ssl/upload', methods=['POST'])
@login_required
@superadmin_required
def admin_ssl_upload():
    cert_upload = request.files.get('cert_file')
    key_upload = request.files.get('key_file')
    if not cert_upload or not key_upload or not cert_upload.filename or not key_upload.filename:
        flash('Both a certificate and a private key file are required.', 'error')
        return redirect(url_for('admin_ssl'))

    cert_bytes = cert_upload.read()
    key_bytes = key_upload.read()

    _cert, error = _validate_cert_pair(cert_bytes, key_bytes)
    if error:
        flash(error, 'error')
        return redirect(url_for('admin_ssl'))

    # Stage both files first, then rename into place, so a mid-write failure never
    # leaves a mismatched cert/key pair that would break TLS startup.
    try:
        os.makedirs(CERT_DIR, exist_ok=True)
        cert_tmp = CERT_FILE + '.tmp'
        key_tmp = KEY_FILE + '.tmp'
        with open(cert_tmp, 'wb') as f:
            f.write(cert_bytes)
        key_fd = os.open(key_tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(key_fd, 'wb') as f:
            f.write(key_bytes)
        os.replace(cert_tmp, CERT_FILE)
        os.replace(key_tmp, KEY_FILE)
        with open(CERT_MANAGED_MARKER, 'w') as f:
            f.write('web-managed; entrypoint will not regenerate this cert\n')
    except OSError as e:
        flash(f'Could not save the certificate: {e}', 'error')
        return redirect(url_for('admin_ssl'))

    _log_api_audit(session.get('user_id'), None, 200, action='ssl_upload')

    if os.getenv('ENABLE_SSL', 'false').lower() != 'true':
        flash('Certificate saved. SSL is disabled (ENABLE_SSL=false); set it to true and restart to serve over HTTPS.', 'success')
    elif _reload_tls():
        flash('Certificate saved and TLS reload signalled. New connections will use the new certificate shortly.', 'success')
    else:
        flash('Certificate saved. Restart the container for it to take effect.', 'success')
    return redirect(url_for('admin_ssl'))


@app.route('/search')
@login_required
def search_cdu():
    query = request.args.get('q', '').strip()
    results = []
    if query:
        # Wildcard search over the latest version's rule_content. Escape LIKE
        # specials in the literal input, then map * -> % and ? -> _. With no
        # wildcard, match as a substring (contains).
        escaped = query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
        if '*' in query or '?' in query:
            pattern = escaped.replace('*', '%').replace('?', '_')
        else:
            pattern = f"%{escaped}%"

        conn = get_db_connection()
        if not conn:
            flash('Database connection failed.', 'error')
            return redirect(url_for('home'))
        cursor = conn.cursor(dictionary=True)
        cf, cfp = company_filter()
        cursor.execute(f"""
            SELECT a.rule_name, a.company, a.environment, a.rule_status, a.mitre,
                   c.version
            FROM archives a
            JOIN (
                SELECT rule_name, company, environment, MAX(id) AS max_id, COUNT(*) AS version
                FROM archives
                WHERE {cf}
                GROUP BY rule_name, company, environment
            ) c ON a.id = c.max_id
            WHERE a.rule_content LIKE %s
            ORDER BY a.rule_name
        """, tuple(cfp) + (pattern,))
        results = cursor.fetchall()
        for row in results:
            m = row.get('mitre')
            if isinstance(m, str):
                try:
                    m = json.loads(m)
                except (json.JSONDecodeError, ValueError):
                    m = None
            row['has_mitre'] = bool(m)
        cursor.close()
        conn.close()

    return render_template('search.html', query=query, results=results)


@app.route('/reports')
@login_required
def reports():
    configs  = load_reports_config()
    report_id = request.args.get('id', '')
    company   = request.args.get('company', '')
    date_from = request.args.get('from', '')
    date_to   = request.args.get('to', '')
    run       = request.args.get('run', '')

    selected = next((c for c in configs if c['id'] == report_id), None)

    if selected and 'from' not in request.args and 'to' not in request.args:
        date_from, date_to = preset_date_range('week')

    preset = detect_preset(date_from, date_to)

    title_map = {
        'week':     'Weekly Report',
        'lastweek': 'Last Week Report',
        'month':    'Monthly Report',
        '7d':       'Last 7 Days Report',
        '30d':      'Last 30 Days Report',
        '90d':      'Last 3 Months Report',
    }
    report_title = title_map.get(preset, 'CDU Report')

    companies = [c['name'] for c in visible_companies()]

    report_data = None
    if selected and run:
        report_data = build_report_data(selected, company, date_from, date_to)

    return render_template('reports.html',
        configs=configs, selected=selected, companies=companies,
        company=company, date_from=date_from, date_to=date_to,
        report_data=report_data, run=run, preset=preset,
        report_title=report_title,
    )


if __name__ == '__main__':
    # Local development only. In containers/production the app is served by
    # gunicorn (see docker/entrypoint.sh); debug is off unless FLASK_DEBUG=true.
    debug = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(debug=debug, host='0.0.0.0', port=5001, use_reloader=debug)