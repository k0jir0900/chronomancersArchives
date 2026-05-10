import os
import secrets
import functools
import hashlib
import json
import atexit
from flask import Flask, render_template, request, redirect, flash, session, url_for, send_file, jsonify
import mysql.connector
from datetime import datetime, timedelta
import calendar
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

import urllib.request
import urllib.error
import threading

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.triggers.interval import IntervalTrigger
    scheduler_available = True
except ImportError:
    scheduler_available = False
    print("Warning: APScheduler not found. Scheduling features disabled.")

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
            filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_db_connection():
    try:
        connection = mysql.connector.connect(
            host=os.getenv('DB_HOST'),
            port=os.getenv('DB_PORT'),
            user=os.getenv('DB_USER'),
            password=os.getenv('DB_PASSWORD'),
            database=os.getenv('DB_NAME')
        )
        return connection
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return None

def sync_mitre_data():
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'chronomancers-archives/1.0'})
        with urllib.request.urlopen(req, timeout=120) as response:
            data = json.loads(response.read().decode('utf-8'))
    except Exception as e:
        print(f"MITRE sync fetch error: {e}")
        return False

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
                   if p.get('kill_chain_name') == 'mitre-attack']
        tactic_str = ','.join(tactics) if tactics else None
        parent_id = tech_id.split('.')[0] if is_subtechnique and '.' in tech_id else None

        techniques.append((tech_id, name, tactic_str, parent_id))

    if not techniques:
        return False

    conn = get_db_connection()
    if not conn:
        return False

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT GET_LOCK('mitre_sync_lock', 0) AS acquired")
        row = cursor.fetchone()
        if not row or not row[0]:
            cursor.close()
            conn.close()
            return False

        try:
            cursor.execute("TRUNCATE TABLE mitre_techniques")
            cursor.executemany(
                "INSERT INTO mitre_techniques (technique_id, name, tactic, parent_id) VALUES (%s, %s, %s, %s)",
                techniques
            )
            cursor.execute("DELETE FROM mitre_sync")
            cursor.execute("INSERT INTO mitre_sync (last_updated) VALUES (NOW())")
            conn.commit()
            print(f"MITRE sync complete: {len(techniques)} techniques stored")
            return True
        except Exception as e:
            print(f"MITRE DB error: {e}")
            return False
        finally:
            cursor.execute("SELECT RELEASE_LOCK('mitre_sync_lock')")
            cursor.fetchone()
    finally:
        cursor.close()
        conn.close()


def startup_mitre_check():
    try:
        conn = get_db_connection()
        if not conn:
            return
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT last_updated FROM mitre_sync ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        cursor.execute("SELECT COUNT(*) as cnt FROM mitre_techniques")
        count_row = cursor.fetchone()
        cursor.close()
        conn.close()

        needs_sync = True
        if row and row['last_updated'] and count_row and count_row['cnt'] > 0:
            days_since = (datetime.now() - row['last_updated']).days
            needs_sync = days_since >= 7

        if needs_sync:
            print("Starting MITRE ATT&CK background sync...")
            t = threading.Thread(target=sync_mitre_data, daemon=True)
            t.start()
    except Exception as e:
        print(f"MITRE startup check error: {e}")


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
            CREATE TABLE IF NOT EXISTS api_keys (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL UNIQUE,
                key_value VARCHAR(67) NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used_at TIMESTAMP NULL DEFAULT NULL,
                INDEX idx_api_keys_value (key_value)
            )
        """)
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
        try:
            cursor.execute("ALTER TABLE api_keys ADD COLUMN key_prefix VARCHAR(11) NULL")
        except mysql.connector.Error:
            pass
        # Migrate existing plaintext keys to SHA-256 hashes
        plain_cursor = conn.cursor()
        plain_cursor.execute("SELECT id, key_value FROM api_keys WHERE LENGTH(key_value) = 67")
        for row in plain_cursor.fetchall():
            row_id, plaintext = row
            key_hash = hashlib.sha256(plaintext.encode()).hexdigest()
            prefix = plaintext[:7]
            plain_cursor.execute(
                "UPDATE api_keys SET key_value = %s, key_prefix = %s WHERE id = %s",
                (key_hash, prefix, row_id)
            )
        plain_cursor.close()

        hashed_password = generate_password_hash('admin')
        cursor.execute(
            "INSERT IGNORE INTO users (username, full_name, password_hash, role) VALUES (%s, %s, %s, %s)",
            ('admin', 'Admin', hashed_password, 'admin')
        )
        conn.commit()
        if cursor.rowcount:
            print("Default admin user created.")

        cursor.close()
        conn.close()

@app.context_processor
def inject_user():
    user = None
    if 'user_id' in session:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            try:
                cursor.execute("SELECT id, username, full_name, role, profile_pic, theme_preference FROM users WHERE id = %s", (session['user_id'],))
                user = cursor.fetchone()
            except:
                try:
                    cursor.execute("SELECT id, username, role, profile_pic FROM users WHERE id = %s", (session['user_id'],))
                    user = cursor.fetchone()
                except:
                    cursor.execute("SELECT id, username, role FROM users WHERE id = %s", (session['user_id'],))
                    user = cursor.fetchone()
            
            cursor.close()
            conn.close()
    return dict(current_user=user)

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
    
    default_start = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d')
    default_end = datetime.now().strftime('%Y-%m-%d')
    
    start_date = request.args.get('start_date', default_start)
    end_date = request.args.get('end_date', default_end)
    
    delta = (datetime.strptime(end_date, '%Y-%m-%d') - datetime.strptime(start_date, '%Y-%m-%d')).days
    filters = {
        'start_date': start_date,
        'end_date': end_date,
        'preset': delta if delta in (7, 15, 30, 90) else None
    }
    
    cursor.execute("SELECT COUNT(DISTINCT rule_name) as unique_total FROM archives WHERE created_at BETWEEN %s AND %s", (start_date + ' 00:00:00', end_date + ' 23:59:59'))
    unique_rules_count = cursor.fetchone()['unique_total']

    cursor.execute("SELECT COUNT(*) as total FROM archives WHERE created_at BETWEEN %s AND %s", (start_date + ' 00:00:00', end_date + ' 23:59:59'))
    total_events = cursor.fetchone()['total']
    
    cursor.execute("SELECT action_type, COUNT(*) as count FROM archives WHERE created_at BETWEEN %s AND %s GROUP BY action_type", (start_date + ' 00:00:00', end_date + ' 23:59:59'))
    action_counts = {row['action_type']: row['count'] for row in cursor.fetchall()}
    
    stats = {
        'unique_rules': unique_rules_count,
        'total': total_events,
        'creation': action_counts.get('creation', 0),
        'modification': action_counts.get('modification', 0),
        'elimination': action_counts.get('elimination', 0)
    }
    
    cursor.execute("SELECT rule_name, COUNT(*) as count FROM archives GROUP BY rule_name ORDER BY count DESC LIMIT 5")
    top_rules = cursor.fetchall()

    cursor.execute("SELECT tuning_driver, COUNT(*) as count FROM archives WHERE tuning_driver IS NOT NULL AND tuning_driver != '' AND created_at BETWEEN %s AND %s GROUP BY tuning_driver", (start_date + ' 00:00:00', end_date + ' 23:59:59'))
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
    
    cursor.execute("""
        SELECT DATE(created_at) as log_date, action_type, COUNT(*) as count 
        FROM archives 
        WHERE created_at BETWEEN %s AND %s
        GROUP BY log_date, action_type 
        ORDER BY log_date ASC
    """, (start_date + ' 00:00:00', end_date + ' 23:59:59'))
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

    cursor.execute("""
        SELECT
            SUM(CASE WHEN a.mitre IS NOT NULL AND a.mitre != 'null' AND a.mitre != '[]' THEN 1 ELSE 0 END) as with_mitre,
            SUM(CASE WHEN a.mitre IS NULL OR a.mitre = 'null' OR a.mitre = '[]' THEN 1 ELSE 0 END) as without_mitre
        FROM archives a
        JOIN (SELECT rule_name, MAX(id) AS max_id FROM archives GROUP BY rule_name) latest ON a.id = latest.max_id
    """)
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

    cursor.execute("SELECT DISTINCT rule_name FROM archives ORDER BY rule_name")
    rules = [row['rule_name'] for row in cursor.fetchall()]

    cursor.execute("SELECT DISTINCT company FROM archives ORDER BY company")
    companies = [row['company'] for row in cursor.fetchall()]

    cursor.execute("SELECT DISTINCT environment FROM archives ORDER BY environment")
    environments = [row['environment'] for row in cursor.fetchall()]

    cursor.execute("""
        SELECT a.rule_name, a.company, a.environment, a.rule_status, a.mitre,
               c.version
        FROM archives a
        JOIN (
            SELECT rule_name, company, environment, MAX(id) AS max_id, COUNT(*) AS version
            FROM archives
            GROUP BY rule_name, company, environment
        ) c ON a.id = c.max_id
        ORDER BY a.rule_name
    """)
    all_rules_metadata = cursor.fetchall()
    for row in all_rules_metadata:
        m = row.get('mitre')
        if isinstance(m, str):
            try:
                m = json.loads(m)
            except (json.JSONDecodeError, ValueError):
                m = None
        row['has_mitre'] = bool(m)

    selected_rule = request.args.get('rule_name')
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
        query_conditions = " AND ".join(conditions)
        cursor.execute(f"SELECT * FROM archives WHERE {query_conditions} ORDER BY created_at DESC", tuple(params))
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
            cursor.execute(chart_query, tuple(params) + (start_date, end_date))
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
    try:
        cursor.execute("UPDATE archives SET mitre = %s WHERE id = %s", (mitre_data, record_id))
        conn.commit()
        flash('MITRE ATT&CK updated.', 'success')
    except Exception as e:
        flash(f'Database error: {e}', 'error')
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
        cursor.execute("UPDATE archives SET tags = %s WHERE id = %s", (tags_data, record_id))
        conn.commit()
        flash('Tags updated.', 'success')
    except Exception as e:
        flash(f'Database error: {e}', 'error')
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
    
    cursor.execute("SELECT rule_name FROM archives GROUP BY rule_name HAVING COUNT(*) >= 2 ORDER BY rule_name")
    all_rules = [row['rule_name'] for row in cursor.fetchall()]
    
    versions = []
    rule1_data = None
    rule2_data = None
    
    if selected_rule:
        cursor.execute("SELECT id, created_at, action_type, modified_by, tuning_driver FROM archives WHERE rule_name = %s ORDER BY created_at ASC", (selected_rule,))
        rows = cursor.fetchall()
        for i, v in enumerate(rows):
            v['version'] = i + 1
        versions = list(reversed(rows))
        
        if v1_id:
            cursor.execute("SELECT rule_content, created_at FROM archives WHERE id = %s", (v1_id,))
            rule1_data = cursor.fetchone()
        
        if v2_id:
            cursor.execute("SELECT rule_content, created_at FROM archives WHERE id = %s", (v2_id,))
            rule2_data = cursor.fetchone()
            
    cursor.close()
    conn.close()
    
    r1_content = rule1_data['rule_content'] if rule1_data and rule1_data['rule_content'] else ''
    r2_content = rule2_data['rule_content'] if rule2_data and rule2_data['rule_content'] else ''
    
    v1_label = f"Version {rule1_data['created_at'].strftime('%Y-%m-%d %H:%M')}" if rule1_data else "Version 1"
    v2_label = f"Version {rule2_data['created_at'].strftime('%Y-%m-%d %H:%M')}" if rule2_data else "Version 2"
    
    r1_json = json.dumps(r1_content)
    r2_json = json.dumps(r2_content)
    
    return render_template('diff.html', all_rules=all_rules, selected_rule=selected_rule, versions=versions, v1_id=v1_id, v2_id=v2_id, rule1_content_json=r1_json, rule2_content_json=r2_json, v1_label=v1_label, v2_label=v2_label)

@app.route('/login', methods=['GET', 'POST'])
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
        company = request.form.get('company')
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

        if not rule_name or not company or not environment or not action_type or not severity or not description or not rule_content:
            flash('All mandatory fields must be filled.', 'error')
            return redirect(url_for('register'))

        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)

            try:
                cursor.execute("SELECT full_name, username FROM users WHERE id = %s", (session['user_id'],))
                user_info = cursor.fetchone()
                modifier_name = user_info['full_name'] if user_info and user_info.get('full_name') else session.get('username')
            except:
                modifier_name = session.get('username')

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

            query = "INSERT INTO archives (rule_name, company, environment, action_type, rule_status, tuning_driver, severity, ticket, description, rule_content, modified_by, mitre, siem, tags) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            values = (rule_name, company, environment, action_type, rule_status, tuning_driver, severity, ticket, description, rule_content, modifier_name, mitre_data, siem, tags_data)

            try:
                cursor.execute(query, values)
                conn.commit()
                flash('Log registered successfully!', 'success')
            except mysql.connector.Error as err:
                flash(f'Database error: {err}', 'error')
            finally:
                cursor.close()
                conn.close()
        else:
            flash('Could not connect to database.', 'error')

        return redirect(url_for('register'))

    conn = get_db_connection()
    rules = []
    if conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT DISTINCT rule_name FROM archives ORDER BY rule_name")
        rules = [r['rule_name'] for r in cursor.fetchall()]
        cursor.close()
        conn.close()
    return render_template('register.html', rules=rules)


@app.route('/api/mitre/techniques')
@login_required
def api_mitre_techniques():
    conn = get_db_connection()
    if not conn:
        return jsonify([])
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT technique_id, name, tactic FROM mitre_techniques "
        "WHERE parent_id IS NULL ORDER BY technique_id"
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
    cursor = conn.cursor(dictionary=True)
    cursor.execute(
        "SELECT technique_id, name FROM mitre_techniques "
        "WHERE parent_id = %s ORDER BY technique_id",
        (technique_id,)
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
    cursor.execute(
        "SELECT company, siem, environment, severity, rule_status FROM archives WHERE rule_name = %s ORDER BY created_at DESC LIMIT 1",
        (rule_name,)
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
    cursor.execute(
        "SELECT mitre FROM archives WHERE rule_name = %s ORDER BY created_at DESC LIMIT 1",
        (rule_name,)
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
    cursor.execute(
        "SELECT tags FROM archives WHERE rule_name = %s ORDER BY created_at DESC LIMIT 1",
        (rule_name,)
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
                flash(f'Error updating profile: {err}', 'error')
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
                    flash(f'Database error: {err}', 'error')
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
                    flash(f'Error updating theme: {err}', 'error')
                finally:
                    if cursor:
                        cursor.close()
            else:
                flash('Invalid theme selected.', 'error')

        return redirect(url_for('profile'))

    cursor = None
    user_data = None
    api_key_data = None
    try:
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT username, full_name, role, profile_pic, theme_preference FROM users WHERE id = %s", (session['user_id'],))
        except:
            cursor.execute("SELECT username, role, profile_pic, theme_preference FROM users WHERE id = %s", (session['user_id'],))
        user_data = cursor.fetchone()
        cursor.execute("SELECT key_value, key_prefix, created_at, last_used_at FROM api_keys WHERE user_id = %s", (session['user_id'],))
        api_key_data = cursor.fetchone()
    finally:
        if cursor:
            cursor.close()
        conn.close()

    revealed_key = session.pop('api_key_reveal', None)
    return render_template('profile.html', user=user_data, api_key=api_key_data, revealed_key=revealed_key)

@app.route('/health')
def health():
    return "OK", 200

try:
    with app.app_context():
        init_db()
        startup_mitre_check()
except Exception as e:
    print(f"Warning: Could not initialize on startup: {e}")

def admin_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        conn = get_db_connection()
        user = None
        if conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT role FROM users WHERE id = %s", (session['user_id'],))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
            
        if not user or user['role'] != 'admin':
            flash('Admin privileges required.', 'error')
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
               k.key_value, k.key_prefix, k.created_at as key_created, k.last_used_at
        FROM users u
        LEFT JOIN api_keys k ON k.user_id = u.id
        ORDER BY u.username
    """)
    users_data = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('users.html', users=users_data)

@app.route('/users/add', methods=['POST'])
@login_required
@admin_required
def add_user():
    username = request.form.get('username')
    full_name = request.form.get('full_name')
    password = request.form.get('password')
    role = request.form.get('role')
    
    if not username or not password or not role:
        flash('Username, password and role are required.', 'error')
        return redirect(url_for('users'))
        
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            hashed_password = generate_password_hash(password)
            cursor.execute("INSERT INTO users (username, full_name, password_hash, role) VALUES (%s, %s, %s, %s)", 
                        (username, full_name, hashed_password, role))
            conn.commit()
            flash('User created successfully.', 'success')
        except mysql.connector.Error as err:
            flash(f'Error creating user: {err}', 'error')
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
        flash(f'Error updating user: {err}', 'error')
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
            cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
            conn.commit()
            flash('User deleted successfully.', 'success')
        except mysql.connector.Error as err:
            flash(f'Error deleting user: {err}', 'error')
        finally:
            cursor.close()
            conn.close()
            
    return redirect(url_for('users'))


@app.route('/users/api-key/regenerate/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_regenerate_api_key(user_id):
    new_key = 'ca_' + secrets.token_hex(32)
    key_hash = hashlib.sha256(new_key.encode()).hexdigest()
    key_prefix = new_key[:7]
    conn = get_db_connection()
    if not conn:
        flash('Database connection failed.', 'error')
        return redirect(url_for('users'))
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "INSERT INTO api_keys (user_id, key_value, key_prefix) VALUES (%s, %s, %s) "
            "ON DUPLICATE KEY UPDATE key_value = VALUES(key_value), key_prefix = VALUES(key_prefix), created_at = NOW(), last_used_at = NULL",
            (user_id, key_hash, key_prefix)
        )
        conn.commit()
        action = 'key_generated' if cursor.rowcount == 1 else 'key_regenerated'
        cursor.execute("SELECT id FROM api_keys WHERE user_id = %s", (user_id,))
        key_row = cursor.fetchone()
        _log_api_audit(user_id, key_row['id'] if key_row else None, None, action)
        flash(f'API key {"generated" if action == "key_generated" else "regenerated"} — new key: {new_key}', 'success')
    except mysql.connector.Error as err:
        flash(f'Error: {err}', 'error')
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for('users'))


@app.route('/users/api-key/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_api_key(user_id):
    conn = get_db_connection()
    if not conn:
        flash('Database connection failed.', 'error')
        return redirect(url_for('users'))
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id FROM api_keys WHERE user_id = %s", (user_id,))
        key_row = cursor.fetchone()
        if key_row:
            _log_api_audit(user_id, key_row['id'], None, 'key_deleted')
            cursor.execute("DELETE FROM api_keys WHERE user_id = %s", (user_id,))
            conn.commit()
            flash('API key deleted.', 'success')
        else:
            flash('No API key found for this user.', 'error')
    except mysql.connector.Error as err:
        flash(f'Error: {err}', 'error')
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for('users'))


BACKUP_FOLDER = os.path.join(os.getcwd(), 'backups')
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
        print(f"Backup Error: {e}")
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

    try:
        cursor = conn.cursor()
        cursor.execute("SET FOREIGN_KEY_CHECKS = 0")

        with open(filepath, 'r', encoding='utf-8') as f:
            sql_script = f.read()

        for statement in _split_sql_statements(sql_script):
            cursor.execute(statement)

        conn.commit()
        cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"Restore Error: {e}")
        return False

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
        flash(f"Database restored from '{filename}'.", "success")
    else:
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
        
    if file and file.filename.endswith('.sql'):
        filename = secure_filename(file.filename)
        file.save(os.path.join(BACKUP_FOLDER, filename))
        flash(f'Backup "{filename}" uploaded successfully.', 'success')
    else:
        flash('Invalid file format. Only .sql files are allowed.', 'error')
        
    return redirect(url_for('list_backups'))

# --- SCHEDULER CONFIGURATION ---

SCHEDULER_CONFIG_FILE = 'backup.conf'
scheduler = None

if scheduler_available:
    try:
        scheduler = BackgroundScheduler()
    except Exception as e:
        print(f"Error initializing scheduler: {e}")
        scheduler_available = False

def load_schedule_config():
    if os.path.exists(SCHEDULER_CONFIG_FILE):
        try:
            with open(SCHEDULER_CONFIG_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_schedule_config(config):
    with open(SCHEDULER_CONFIG_FILE, 'w') as f:
        json.dump(config, f)

def scheduled_backup_job():
    with app.app_context():
        filename = f"auto_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sql"
        filepath = os.path.join(BACKUP_FOLDER, filename)
        print(f"Running Scheduled Backup: {filename}")
        generate_backup_custom(filepath)

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
            print("Invalid time format in schedule config.")
    else:
        if scheduler.get_job('backup_job'):
            scheduler.remove_job('backup_job')

if scheduler_available:
    init_scheduler()
    if scheduler:
        try:
            scheduler.add_job(
                func=sync_mitre_data,
                trigger=IntervalTrigger(days=7),
                id='mitre_sync_job',
                name='MITRE ATT&CK Sync',
                replace_existing=True
            )
            if not scheduler.running:
                scheduler.start()
        except Exception as e:
            print(f"MITRE scheduler error: {e}")

        def safe_shutdown():
            if scheduler.running:
                scheduler.shutdown()
        atexit.register(safe_shutdown)

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

    config = {
        'enabled': enabled,
        'frequency': frequency,
        'time': backup_time
    }
    
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


def require_api_key(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get('X-API-Key', '').strip()
        if not key:
            _log_api_audit(None, None, 401, 'auth_failed')
            return jsonify({'error': 'Missing X-API-Key header'}), 401
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Service unavailable'}), 503
        cursor = conn.cursor(dictionary=True)
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        cursor.execute("SELECT id, user_id FROM api_keys WHERE key_value = %s", (key_hash,))
        row = cursor.fetchone()
        if not row:
            cursor.close()
            conn.close()
            _log_api_audit(None, None, 403, 'auth_failed')
            return jsonify({'error': 'Invalid API key'}), 403
        cursor.execute("UPDATE api_keys SET last_used_at = NOW() WHERE id = %s", (row['id'],))
        conn.commit()
        cursor.close()
        conn.close()
        resp = f(*args, **kwargs)
        status = resp[1] if isinstance(resp, tuple) else 200
        _log_api_audit(row['user_id'], row['id'], status, 'api_call')
        return resp
    return decorated


@app.route('/profile/api-key/generate', methods=['POST'])
@login_required
def generate_api_key():
    new_key = 'ca_' + secrets.token_hex(32)
    key_hash = hashlib.sha256(new_key.encode()).hexdigest()
    key_prefix = new_key[:7]
    conn = get_db_connection()
    if not conn:
        flash('Database connection failed.', 'error')
        return redirect(url_for('profile'))
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO api_keys (user_id, key_value, key_prefix) VALUES (%s, %s, %s) "
            "ON DUPLICATE KEY UPDATE key_value = VALUES(key_value), key_prefix = VALUES(key_prefix), created_at = NOW(), last_used_at = NULL",
            (session['user_id'], key_hash, key_prefix)
        )
        conn.commit()
        # rowcount=1 means INSERT (new key), rowcount=2 means UPDATE (regenerated)
        action = 'key_generated' if cursor.rowcount == 1 else 'key_regenerated'
        session['api_key_reveal'] = new_key
        cursor2 = conn.cursor(dictionary=True)
        cursor2.execute("SELECT id FROM api_keys WHERE user_id = %s", (session['user_id'],))
        key_row = cursor2.fetchone()
        cursor2.close()
        _log_api_audit(session['user_id'], key_row['id'] if key_row else None, None, action)
    except mysql.connector.Error as err:
        flash(f'Error generating API key: {err}', 'error')
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for('profile'))


@app.route('/api/v1/cdu')
@require_api_key
def api_export_cdu():
    company = request.args.get('company', '').strip()
    try:
        page = max(1, int(request.args.get('page', 1)))
        limit = min(500, max(1, int(request.args.get('limit', 100))))
    except ValueError:
        return jsonify({'error': 'Invalid pagination parameters'}), 400
    offset = (page - 1) * limit

    conn = get_db_connection()
    if not conn:
        return jsonify({'error': 'Service unavailable'}), 503
    cursor = conn.cursor(dictionary=True)

    conditions, params = [], []
    if company:
        conditions.append("company = %s")
        params.append(company)
    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    cursor.execute(f"SELECT COUNT(*) as total FROM archives {where}", tuple(params))
    total = cursor.fetchone()['total']
    cursor.execute(
        f"SELECT id, rule_name, company, environment, action_type, rule_status, tuning_driver, "
        f"ticket, description, rule_content, modified_by, mitre, siem, tags, created_at "
        f"FROM archives {where} ORDER BY created_at DESC LIMIT %s OFFSET %s",
        tuple(params) + (limit, offset)
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    records = []
    for row in rows:
        mitre = row['mitre']
        if mitre and isinstance(mitre, str):
            try:
                mitre = json.loads(mitre)
            except (json.JSONDecodeError, ValueError):
                mitre = []
        tags = row['tags']
        if tags and isinstance(tags, str):
            try:
                tags = json.loads(tags)
            except (json.JSONDecodeError, ValueError):
                tags = []
        records.append({
            'id': row['id'],
            'rule_name': row['rule_name'],
            'company': row['company'],
            'environment': row['environment'],
            'action_type': row['action_type'],
            'rule_status': row['rule_status'],
            'tuning_driver': row['tuning_driver'],
            'ticket': row['ticket'],
            'description': row['description'],
            'rule_content': row['rule_content'],
            'modified_by': row['modified_by'],
            'mitre': mitre or [],
            'siem': row['siem'],
            'tags': tags or [],
            'created_at': row['created_at'].isoformat() if row['created_at'] else None
        })

    return jsonify({
        'total': total,
        'page': page,
        'limit': limit,
        'pages': (total + limit - 1) // limit,
        'data': records
    })


@app.route('/api/docs')
@login_required
def api_docs():
    return render_template('api_docs.html')


@app.route('/api/openapi.json')
def api_openapi():
    base = request.host_url.rstrip('/')
    spec = {
        "openapi": "3.0.0",
        "info": {
            "title": "Chronomancers Archives API",
            "version": "1.0.0",
            "description": "REST API to export CDU (Correlation Detection Unit) records from Chronomancers Archives."
        },
        "servers": [{"url": base, "description": "Current server"}],
        "security": [{"ApiKeyAuth": []}],
        "components": {
            "securitySchemes": {
                "ApiKeyAuth": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key",
                    "description": "API key generated from your profile page. Format: `ca_<64 hex chars>`"
                }
            },
            "schemas": {
                "CDU": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "integer", "example": 42},
                        "rule_name": {"type": "string", "example": "Windows Brute Force"},
                        "company": {"type": "string", "example": "Acme Corp"},
                        "environment": {"type": "string", "enum": ["IT", "OT", "Both"]},
                        "action_type": {"type": "string", "enum": ["creation", "modification", "elimination"]},
                        "rule_status": {"type": "string", "enum": ["active", "disabled"]},
                        "tuning_driver": {"type": "string", "enum": ["fp_correction", "hardening", "new_use_case", "maintenance"]},
                        "ticket": {"type": "string", "nullable": True, "example": "TKT-1234"},
                        "description": {"type": "string"},
                        "rule_content": {"type": "string"},
                        "modified_by": {"type": "string"},
                        "mitre": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": ["T1110", "T1078:T1078.004"]
                        },
                        "siem": {"type": "string", "nullable": True, "example": "crowdstrike"},
                        "tags": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": ["baseline:gold", "os_family:linux"]
                        },
                        "created_at": {"type": "string", "format": "date-time"}
                    }
                },
                "CDUListResponse": {
                    "type": "object",
                    "properties": {
                        "total": {"type": "integer"},
                        "page": {"type": "integer"},
                        "limit": {"type": "integer"},
                        "pages": {"type": "integer"},
                        "data": {"type": "array", "items": {"$ref": "#/components/schemas/CDU"}}
                    }
                },
                "Error": {
                    "type": "object",
                    "properties": {"error": {"type": "string"}}
                }
            }
        },
        "paths": {
            "/api/v1/cdu": {
                "get": {
                    "summary": "Export CDU records",
                    "description": "Returns a paginated list of CDU records. Optionally filter by company.",
                    "operationId": "exportCDU",
                    "security": [{"ApiKeyAuth": []}],
                    "parameters": [
                        {
                            "name": "company",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string"},
                            "description": "Filter by exact company name"
                        },
                        {
                            "name": "page",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "integer", "default": 1, "minimum": 1},
                            "description": "Page number (starts at 1)"
                        },
                        {
                            "name": "limit",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "integer", "default": 100, "minimum": 1, "maximum": 500},
                            "description": "Records per page (max 500)"
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Paginated CDU records",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/CDUListResponse"}
                                }
                            }
                        },
                        "400": {
                            "description": "Invalid parameters",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
                        },
                        "401": {
                            "description": "Missing API key",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
                        },
                        "403": {
                            "description": "Invalid API key",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}
                        }
                    }
                }
            }
        }
    }
    return jsonify(spec)


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


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001, use_reloader=True)