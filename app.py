import os
import functools
import json
import atexit
from flask import Flask, render_template, request, redirect, flash, session, url_for, send_file
import mysql.connector
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv

# Try to import APScheduler
try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    scheduler_available = True
except ImportError:
    scheduler_available = False
    print("Warning: APScheduler not found. Scheduling features disabled.")

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')

# Configuration for Uploads
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
            filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Database Connection
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

# Auth Decorator
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

# Initialize DB and Default User
def init_db():
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        
        # Check if default admin exists
        cursor.execute("SELECT * FROM users WHERE username = %s", ('admin',))
        user = cursor.fetchone()
        if not user:
            hashed_password = generate_password_hash('admin')
            try:
                # Try inserting with full_name and role
                cursor.execute("INSERT INTO users (username, full_name, password_hash, role) VALUES (%s, %s, %s, %s)", ('admin', 'Admin', hashed_password, 'Admin'))
                conn.commit()
                print("Default admin user created.")
            except mysql.connector.Error:
                # Fallback for old schema
                try:
                    cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)", ('admin', hashed_password, 'Admin'))
                    conn.commit()
                except:
                    print("Could not create default user (check schema)")

        # Migration: Add theme_preference column if not exists
        try:
            cursor.execute("SHOW COLUMNS FROM users LIKE 'theme_preference'")
            if not cursor.fetchone():
                cursor.execute("ALTER TABLE users ADD COLUMN theme_preference VARCHAR(20) DEFAULT 'dark'")
                conn.commit()
                print("Added theme_preference column to users table.")
        except mysql.connector.Error as err:
            print(f"Migration error: {err}")

        cursor.close()
        conn.close()

# Context Processor to inject user data into all templates
@app.context_processor
def inject_user():
    user = None
    if 'user_id' in session:
        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            # Fetch full_name as well
            try:
                cursor.execute("SELECT username, full_name, role, profile_pic, theme_preference FROM users WHERE id = %s", (session['user_id'],))
                user = cursor.fetchone()
            except:
                # Fallback if full_name missing
                try:
                    cursor.execute("SELECT username, role, profile_pic FROM users WHERE id = %s", (session['user_id'],))
                    user = cursor.fetchone()
                except:
                    # Fallback if profile_pic also missing
                    cursor.execute("SELECT username, role FROM users WHERE id = %s", (session['user_id'],))
                    user = cursor.fetchone()
            
            cursor.close()
            conn.close()
    return dict(current_user=user)

# Routes
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
    
    # Date Filtering
    from datetime import datetime, timedelta
    
    # Default to last 30 days
    default_start = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
    default_end = datetime.now().strftime('%Y-%m-%d')
    
    start_date = request.args.get('start_date', default_start)
    end_date = request.args.get('end_date', default_end)
    
    # Filter dictionary for template
    filters = {
        'start_date': start_date,
        'end_date': end_date
    }
    
    # 0. Total Unique Rules (Unfiltered)
    cursor.execute("SELECT COUNT(DISTINCT rule_name) as unique_total FROM archives")
    unique_rules_count = cursor.fetchone()['unique_total']

    # 1. Total Events
    cursor.execute("SELECT COUNT(*) as total FROM archives WHERE created_at BETWEEN %s AND %s", (start_date + ' 00:00:00', end_date + ' 23:59:59'))
    total_events = cursor.fetchone()['total']
    
    # 2. Counts by Action Type
    cursor.execute("SELECT action_type, COUNT(*) as count FROM archives WHERE created_at BETWEEN %s AND %s GROUP BY action_type", (start_date + ' 00:00:00', end_date + ' 23:59:59'))
    action_counts = {row['action_type']: row['count'] for row in cursor.fetchall()}
    
    # Ensure all keys exist for templates
    stats = {
        'unique_rules': unique_rules_count,
        'total': total_events,
        'creation': action_counts.get('creation', 0),
        'modification': action_counts.get('modification', 0),
        'elimination': action_counts.get('elimination', 0)
    }
    
    # 3. Top Rules for Pie Chart (Top 5 Active)
    cursor.execute("SELECT rule_name, COUNT(*) as count FROM archives WHERE created_at BETWEEN %s AND %s GROUP BY rule_name ORDER BY count DESC LIMIT 5", (start_date + ' 00:00:00', end_date + ' 23:59:59'))
    top_rules = cursor.fetchall()

    # 4. Tuning Drivers for Pie Chart
    # Check if 'tuning_driver' column exists (for backward compatibility)
    # Process Tuning Drivers for Pie Chart (Middle Card)
    cursor.execute("SELECT tuning_driver, COUNT(*) as count FROM archives WHERE tuning_driver IS NOT NULL AND tuning_driver != '' GROUP BY tuning_driver")
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
    
    # 5. Daily Stats for Chart (Stacked Bar)
    cursor.execute("""
        SELECT DATE(created_at) as log_date, action_type, COUNT(*) as count 
        FROM archives 
        WHERE created_at BETWEEN %s AND %s
        GROUP BY log_date, action_type 
        ORDER BY log_date ASC
    """, (start_date + ' 00:00:00', end_date + ' 23:59:59'))
    daily_rows = cursor.fetchall()
    
    # Process for Chart.js
    # We need a list of unique dates (labels) and data arrays for each action type
    # If no data exists for a range, we might want to fill gaps, but for now let's just show present data
    # Better yet, generate range of dates?
    # For simplicity, we use unique dates found in DB + maybe start/end if empty?
    # Let's stick to dates with data for now, or just filtered logic.
    
    dates = sorted(list(set(str(row['log_date']) for row in daily_rows)))
    
    chart_data = {
        'labels': dates,
        'datasets': {
            'creation': [0] * len(dates),
            'modification': [0] * len(dates),
            'elimination': [0] * len(dates)
        }
    }
    
    # Map dates to indices
    date_to_idx = {date: i for i, date in enumerate(dates)}
    
    for row in daily_rows:
        d = str(row['log_date'])
        a = row['action_type']
        c = row['count']
        if d in date_to_idx and a in chart_data['datasets']:
            chart_data['datasets'][a][date_to_idx[d]] = c

    cursor.close()
    conn.close()

    return render_template('home.html', stats=stats, top_rules=top_rules, tuning_driver_data=tuning_driver_data, chart_data=chart_data, filters=filters)

@app.route('/history')
@login_required
def history():
    conn = get_db_connection()
    if not conn:
        flash('Database connection failed.', 'error')
        return redirect(url_for('home'))

    cursor = conn.cursor(dictionary=True)

    # 1. Fetch distinct rule names for the dropdown
    cursor.execute("SELECT DISTINCT rule_name FROM archives ORDER BY rule_name")
    rules = [row['rule_name'] for row in cursor.fetchall()]

    selected_rule = request.args.get('rule_name')
    timeline_data = []
    summary = {}

    if selected_rule:
        # 2. Fetch all records for the selected rule
        cursor.execute("SELECT * FROM archives WHERE rule_name = %s ORDER BY created_at DESC", (selected_rule,))
        timeline_data = cursor.fetchall()
        
        if timeline_data:
            # 3. Calculate Summary Stats
            latest = timeline_data[0]
            oldest = timeline_data[-1]
            
            summary = {
                'rule_name': selected_rule,
                'first_created': oldest['created_at'],
                'last_modified': latest['created_at'],
                'current_status': latest['rule_status'],
                'total_events': len(timeline_data),
                'creator': oldest.get('modified_by', 'Unknown'),
                'last_modifier': latest.get('modified_by', 'Unknown')
            }
            
            # 4. Prepare Chart Data (Time Window: Start of Creation Month -> End of Modification Month)
            from datetime import timedelta
            import calendar
            
            start_date = oldest['created_at'].replace(day=1)
            last_day = calendar.monthrange(latest['created_at'].year, latest['created_at'].month)[1]
            end_date = latest['created_at'].replace(day=last_day)
            
            # Query for daily counts within this range for this rule
            chart_query = """
                SELECT 
                    DATE(created_at) as date,
                    SUM(CASE WHEN action_type = 'creation' THEN 1 ELSE 0 END) as created,
                    SUM(CASE WHEN action_type = 'modification' THEN 1 ELSE 0 END) as modified,
                    SUM(CASE WHEN action_type = 'elimination' THEN 1 ELSE 0 END) as deleted
                FROM archives 
                WHERE rule_name = %s AND created_at >= %s AND created_at <= %s + INTERVAL 1 DAY
                GROUP BY DATE(created_at)
                ORDER BY DATE(created_at) ASC
            """
            cursor.execute(chart_query, (selected_rule, start_date, end_date))
            daily_stats = cursor.fetchall()
            
            # Fill in missing days
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
    
    cursor.close()
    conn.close()
    
    return render_template('history.html', rules=rules, selected_rule=selected_rule, timeline=timeline_data, summary=summary, chart_data=chart_data if selected_rule and timeline_data else None)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        conn = get_db_connection()
        user = None
        if conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            cursor.close()
            conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']  # Store username for auditing
            return redirect(url_for('home'))
        
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
        action_type = request.form.get('action_type')
        rule_status = request.form.get('rule_status', 'active')
        tuning_driver = request.form.get('tuning_driver', 'maintenance')
        ticket = request.form.get('ticket')
        description = request.form.get('description')
        rule_content = request.form.get('rule_content')

        if not rule_name or not action_type or not description or not rule_content:
            flash('All mandatory fields must be filled.', 'error')
            return redirect(url_for('register'))

        conn = get_db_connection()
        if conn:
            cursor = conn.cursor(dictionary=True)
            
            # Fetch User's Real Name
            try:
                cursor.execute("SELECT full_name, username FROM users WHERE id = %s", (session['user_id'],))
                user_info = cursor.fetchone()
                # Use full_name if available, otherwise username
                modifier_name = user_info['full_name'] if user_info and user_info.get('full_name') else session.get('username')
            except:
                modifier_name = session.get('username')

            # Insert into Archives
            query = "INSERT INTO archives (rule_name, action_type, rule_status, tuning_driver, ticket, description, rule_content, modified_by) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
            values = (rule_name, action_type, rule_status, tuning_driver, ticket, description, rule_content, modifier_name)
            
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

    return render_template('register.html')

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
            # Only update full_name, NOT username
            full_name = request.form.get('full_name')
            file = request.files.get('profile_pic')
            
            try:
                cursor = conn.cursor()
                
                # Update Full Name
                cursor.execute("UPDATE users SET full_name = %s WHERE id = %s", (full_name, session['user_id']))
                
                # Handle File Upload
                if file and file.filename != '' and allowed_file(file.filename):
                    filename = secure_filename(f"user_{session['user_id']}_{file.filename}")
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    cursor.execute("UPDATE users SET profile_pic = %s WHERE id = %s", (filename, session['user_id']))
                
                conn.commit()
                flash('Profile updated successfully!', 'success')
            except mysql.connector.Error as err:
                flash(f'Error updating profile: {err}', 'error')
            finally:
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
                except mysql.connector.Error as err:
                    flash(f'Database error: {err}', 'error')
                finally:
                    cursor.close()

        elif action == 'update_theme':
            theme = request.form.get('theme')
            if theme in ['dark', 'light']:
                try:
                    cursor = conn.cursor()
                    cursor.execute("UPDATE users SET theme_preference = %s WHERE id = %s", (theme, session['user_id']))
                    conn.commit()
                    flash(f'Theme updated to {theme.title()} Mode.', 'success')
                except mysql.connector.Error as err:
                    flash(f'Error updating theme: {err}', 'error')
                finally:
                    cursor.close()
            else:
                flash('Invalid theme selected.', 'error')

        return redirect(url_for('profile'))

    # GET request
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT username, full_name, role, profile_pic, theme_preference FROM users WHERE id = %s", (session['user_id'],))
    except:
        cursor.execute("SELECT username, role, profile_pic, theme_preference FROM users WHERE id = %s", (session['user_id'],))
    
    user_data = cursor.fetchone()
    cursor.close()
    conn.close()
    
    return render_template('profile.html', user=user_data)

@app.route('/health')
def health():
    return "OK", 200

# Attempt to initialize DB on startup
try:
    with app.app_context():
        init_db()
except Exception as e:
    print(f"Warning: Could not initialize DB on startup: {e}")

# Admin Required Decorator
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
            
        if not user or user['role'] != 'Admin':
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
    cursor.execute("SELECT * FROM users ORDER BY username")
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


# Validations for Backup
BACKUP_FOLDER = os.path.join(os.getcwd(), 'backups')
if not os.path.exists(BACKUP_FOLDER):
    os.makedirs(BACKUP_FOLDER)

# Helper function to generate SQL dump (Python-based)
def generate_backup_custom(filepath):
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cursor = conn.cursor()
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"-- Chronomancers Archives Backup\n")
            f.write(f"-- Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Get Tables
            cursor.execute("SHOW TABLES")
            tables = [table[0] for table in cursor.fetchall()]
            
            for table_name in tables:
                # Get Schema
                cursor.execute(f"SHOW CREATE TABLE {table_name}")
                create_table_sql = cursor.fetchone()[1]
                f.write(f"DROP TABLE IF EXISTS `{table_name}`;\n")
                f.write(f"{create_table_sql};\n\n")
                
                # Get Data
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
                                # Escape single quotes and backslashes
                                escaped_val = str(val).replace("\\", "\\\\").replace("'", "\\'")
                                row_values.append(f"'{escaped_val}'")
                        values_list.append(f"({', '.join(row_values)})")
                    f.write(",\n".join(values_list))
                    f.write(";\n\n")
            
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"Backup Error: {e}")
        return False

# Function to restore from SQL dump
def restore_backup_custom(filepath):
    conn = get_db_connection()
    if not conn:
        return False
        
    try:
        cursor = conn.cursor()
        # Disable foreign key checks temporarily
        cursor.execute("SET FOREIGN_KEY_CHECKS = 0;")
        
        with open(filepath, 'r', encoding='utf-8') as f:
            sql_script = f.read()
            
        # Parse and execute (Split by semicolon, but handle cases carefuly)
        # Simple split might break if data contains semicolon. 
        # For this simple implementation we assume standard SQL dumps generated by us.
        statements = sql_script.split(';')
        for statement in statements:
            if statement.strip():
                cursor.execute(statement)

        conn.commit()
        cursor.execute("SET FOREIGN_KEY_CHECKS = 1;")
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
                # Size in MB
                size_mb = os.path.getsize(path) / (1024 * 1024)
                backups.append({
                    'name': f,
                    'size': f"{size_mb:.2f} MB",
                    'date': created_time
                })
    # Sort by date desc
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
        # Auto-generate filename
        filename = f"auto_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sql"
        filepath = os.path.join(BACKUP_FOLDER, filename)
        print(f"Running Scheduled Backup: {filename}")
        generate_backup_custom(filepath)

def init_scheduler():
    if not scheduler_available or not scheduler:
        return

    config = load_schedule_config()
    if config.get('enabled'):
        frequency = config.get('frequency') # 'daily', 'weekly'
        time = config.get('time', '00:00')
        try:
            hour, minute = time.split(':')
            
            trigger = None
            if frequency == 'daily':
                trigger = CronTrigger(hour=hour, minute=minute)
            elif frequency == 'weekly':
                # Default to Monday for weekly
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

# Initialize scheduler on startup
if scheduler_available:
    init_scheduler()
    if scheduler:
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
    time = request.form.get('time')
    
    config = {
        'enabled': enabled,
        'frequency': frequency,
        'time': time
    }
    
    save_schedule_config(config)
    init_scheduler() # Reload job
    
    flash('Programación de respaldo actualizada.', 'success')
    return redirect(url_for('list_backups'))

# Pass schedule config to template
@app.context_processor
def inject_schedule_config():
    if request.endpoint == 'list_backups':
        return dict(schedule_config=load_schedule_config())
    return dict()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)