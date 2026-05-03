
import mysql.connector
import random
import uuid
import os
import json
from datetime import datetime, timedelta

# Database Configuration (Defaults or Env Vars)
DB_HOST = os.getenv('DB_HOST', 'localhost') # Default to localhost if running outside container, or change if running inside
# Note: If running from host machine against docker mapped port, might need 127.0.0.1 and port 3306 (or whatever is mapped)
# But user said "create a script", likely to run it. If running from OUTSIDE, we might need to know the port.
# Assuming standard setup or user runs it in a way that can access the DB. 
# For now, I'll use standard defaults but allow overrides.
DB_USER = os.getenv('DB_USER', 'chronomancer')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'password')
DB_NAME = os.getenv('DB_NAME', 'chronomancers_db')
DB_PORT = os.getenv('DB_PORT', '3306')

# Sigma Template
SIGMA_TEMPLATE = """
# ./rules/{category}/{service}/{rule_name_normalized}.yml
title: {rule_title}
id: {rule_id}
status: test
description: Detects when {description_text}.
references:
    - https://developer.okta.com/docs/reference/api/system-log/
    - https://developer.okta.com/docs/reference/api/event-types/
author: {author}
date: {created_date}
modified: {modified_date}
tags:
    - attack.impact
logsource:
    product: {service}
    service: {service}
detection:
    selection:
        displaymessage: {detection_msg}
    condition: selection
falsepositives:
    - Unknown
level: medium
"""

# Categorias y Servicios para generar nombres realistas
CATEGORIES = ['cloud', 'network', 'endpoint', 'proxy', 'web']
SERVICES = ['okta', 'aws', 'azure', 'windows', 'linux', 'cisco', 'nginx']
ACTIONS = ['Login Failure', 'Brute Force', 'Privilege Escalation', 'Malware Download', 'Port Scan', 'SQL Injection', 'Ransomware Activity', 'Shadow Copy Deletion']
TUNING_DRIVERS = ['fp_correction', 'hardening', 'new_use_case', 'maintenance']
AUTHORS = ['Kaladin, Stormblessed', 'Kelsier, the Survivor of Hathsin', 'Vin, the Heir to the Ascension', 'Shallan Davar, Lightweaver', 'Dalinar Kholin, the Blackthorn', 'Sazed, the Keeper', 'Raoden, Prince of Elantris', 'Siri, Vessel of the Returned', 'Adolin Kholin, Prince’s Duelist', 'Hoid, Wit']
COMPANIES = ['Acme Corp', 'Stark Industries', 'Wayne Enterprises', 'Umbrella Corporation', 'Cyberdyne Systems']
ENVIRONMENTS = ['IT', 'OT']

# Realistic MITRE ATT&CK technique/subtechnique pairs (technique_id: [subtechnique_id, ...])
MITRE_POOL = {
    'T1059': ['T1059.001', 'T1059.003', 'T1059.004'],
    'T1078': ['T1078.001', 'T1078.002', 'T1078.004'],
    'T1110': ['T1110.001', 'T1110.003'],
    'T1055': ['T1055.001', 'T1055.012'],
    'T1003': ['T1003.001', 'T1003.002'],
    'T1190': [],
    'T1566': ['T1566.001', 'T1566.002'],
    'T1486': [],
    'T1489': [],
    'T1548': ['T1548.002'],
}
MITRE_TECHNIQUES = list(MITRE_POOL.keys())

def random_mitre():
    count = random.randint(1, 3)
    chosen = random.sample(MITRE_TECHNIQUES, min(count, len(MITRE_TECHNIQUES)))
    keys = []
    for tech in chosen:
        subs = MITRE_POOL[tech]
        if subs and random.random() < 0.6:
            sub = random.choice(subs)
            keys.append(f"{tech}:{sub}")
        else:
            keys.append(tech)
    return json.dumps(keys)

def generate_random_date(start_date, end_date):
    time_between_dates = end_date - start_date
    days_between_dates = time_between_dates.days
    random_number_of_days = random.randrange(days_between_dates)
    random_date = start_date + timedelta(days=random_number_of_days)
    # Add random time
    random_time = timedelta(hours=random.randint(0, 23), minutes=random.randint(0, 59), seconds=random.randint(0, 59))
    return random_date + random_time

def connect_db():
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        port=DB_PORT
    )

def main():
    print("Generating mock data...")
    conn = connect_db()
    cursor = conn.cursor()

    # Timeframe: Last 3 months (90 days)
    end_date = datetime.now()
    start_date = end_date - timedelta(days=90)

    # 1. Generate ~50 Base Rules
    rules = []
    for _ in range(50):
        category = random.choice(CATEGORIES)
        service = random.choice(SERVICES)
        action = random.choice(ACTIONS)
        rule_title = f"{service.capitalize()} {action}"
        rules.append({
            "title": rule_title,
            "category": category,
            "service": service,
            "id": str(uuid.uuid4()),
            "company": random.choice(COMPANIES),
            "environment": random.choice(ENVIRONMENTS)
        })

    # 2. Simulate History
    # sort by date not strictly necessary for insert, but good for logic
    
    events = []

    for rule in rules:
        # Creation Event (Must be first)
        created_at = generate_random_date(start_date, end_date - timedelta(days=10)) # Leave room for mods
        creator = random.choice(AUTHORS)
        
        rule_mitre = random_mitre()
        creation_event = {
            "rule_name": rule["title"],
            "company": rule["company"],
            "environment": rule["environment"],
            "action_type": "creation",
            "rule_status": "active",
            "tuning_driver": "new_use_case",
            "ticket": f"TKT-{random.randint(1000, 9999)}",
            "description": f"Initial creation of {rule['title']}",
            "rule_content": SIGMA_TEMPLATE.format(
                category=rule["category"],
                service=rule["service"],
                rule_name_normalized=rule["title"].lower().replace(' ', '_'),
                rule_title=rule["title"],
                rule_id=rule["id"],
                description_text=f"a {rule['title']} occurs",
                author=creator,
                created_date=created_at.strftime("%Y-%m-%d"),
                modified_date=created_at.strftime("%Y-%m-%d"),
                detection_msg=f"{rule['title']} detected"
            ),
            "modified_by": creator,
            "created_at": created_at,
            "mitre": rule_mitre
        }
        events.append(creation_event)

        # Modifications (0 to 5 times)
        num_mods = random.randint(0, 5)
        current_date = created_at
        
        for i in range(num_mods):
            # Advance time slightly
            if (end_date - current_date).days < 1:
                break
            
            try:
                mod_date = generate_random_date(current_date + timedelta(hours=1), end_date)
            except ValueError:
                break # Close to end date

            current_date = mod_date
            modifier = random.choice(AUTHORS)
            driver = random.choice(TUNING_DRIVERS)
            
            if random.random() < 0.4:
                rule_mitre = random_mitre()
            mod_event = {
                "rule_name": rule["title"],
                "company": rule["company"],
                "environment": rule["environment"],
                "action_type": "modification",
                "rule_status": "active",
                "tuning_driver": driver,
                "ticket": f"TKT-{random.randint(1000, 9999)}",
                "description": f"Tuning update: {driver} applied.",
                "rule_content": SIGMA_TEMPLATE.format(
                    category=rule["category"],
                    service=rule["service"],
                    rule_name_normalized=rule["title"].lower().replace(' ', '_'),
                    rule_title=rule["title"],
                    rule_id=rule["id"],
                    description_text=f"a {rule['title']} occurs (v{i+2})",
                    author=creator,
                    created_date=created_at.strftime("%Y-%m-%d"),
                    modified_date=mod_date.strftime("%Y-%m-%d"),
                    detection_msg=f"{rule['title']} detected (tuned)"
                ),
                "modified_by": modifier,
                "created_at": mod_date,
                "mitre": rule_mitre
            }
            events.append(mod_event)

        # Elimination (10% chance)
        if random.random() < 0.10:
             if (end_date - current_date).days >= 1:
                del_date = generate_random_date(current_date + timedelta(hours=1), end_date)
                deleter = random.choice(AUTHORS)
                
                del_event = {
                    "rule_name": rule["title"],
                    "company": rule["company"],
                    "environment": rule["environment"],
                    "action_type": "elimination",
                    "rule_status": "disabled",
                    "tuning_driver": "maintenance",
                    "ticket": f"TKT-{random.randint(1000, 9999)}",
                    "description": "Rule deprecated/removed.",
                    "rule_content": "DELETED",
                    "modified_by": deleter,
                    "created_at": del_date,
                    "mitre": rule_mitre
                }
                events.append(del_event)

    # Insert events
    print(f"Inserting {len(events)} events...")
    
    # Sort by date so insertion order looks roughly chronological (optional ID order)
    events.sort(key=lambda x: x['created_at'])

    sql = """
    INSERT INTO archives
    (rule_name, company, environment, action_type, rule_status, tuning_driver, ticket, description, rule_content, modified_by, created_at, mitre)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    for e in events:
        val = (
            e['rule_name'],
            e['company'],
            e['environment'],
            e['action_type'],
            e['rule_status'],
            e['tuning_driver'],
            e['ticket'],
            e['description'],
            e['rule_content'],
            e['modified_by'],
            e['created_at'],
            e.get('mitre')
        )
        cursor.execute(sql, val)

    conn.commit()
    print("Data generation complete.")
    cursor.close()
    conn.close()

if __name__ == "__main__":
    main()
