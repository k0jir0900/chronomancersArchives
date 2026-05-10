CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    full_name VARCHAR(255) DEFAULT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'User',
    profile_pic VARCHAR(255) DEFAULT NULL,
    theme_preference VARCHAR(20) DEFAULT 'dark',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS archives (
    id INT AUTO_INCREMENT PRIMARY KEY,
    rule_name VARCHAR(255) NOT NULL,
    company VARCHAR(255) NOT NULL,
    environment VARCHAR(50) NOT NULL,
    rule_status VARCHAR(20) DEFAULT 'active',
    tuning_driver VARCHAR(50) DEFAULT 'maintenance',
    severity VARCHAR(20) DEFAULT NULL,
    action_type ENUM('creation', 'modification', 'elimination') NOT NULL,
    ticket VARCHAR(255),
    description TEXT NOT NULL,
    rule_content TEXT NOT NULL,
    modified_by VARCHAR(100),
    mitre JSON DEFAULT NULL,
    siem VARCHAR(50) DEFAULT NULL,
    tags JSON DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_rule_name (rule_name),
    INDEX idx_created_at (created_at),
    INDEX idx_tuning_driver (tuning_driver),
    INDEX idx_action_type (action_type)
);

CREATE TABLE IF NOT EXISTS mitre_techniques (
    id INT AUTO_INCREMENT PRIMARY KEY,
    technique_id VARCHAR(20) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    tactic VARCHAR(500) DEFAULT NULL,
    parent_id VARCHAR(20) DEFAULT NULL,
    INDEX idx_mitre_parent (parent_id)
);

CREATE TABLE IF NOT EXISTS mitre_sync (
    id INT AUTO_INCREMENT PRIMARY KEY,
    last_updated TIMESTAMP DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS tags_pool (
    id INT AUTO_INCREMENT PRIMARY KEY,
    category VARCHAR(50) NOT NULL,
    value VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_cat_value (category, value),
    INDEX idx_tag_category (category)
);