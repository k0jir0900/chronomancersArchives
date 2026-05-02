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
    action_type ENUM('creation', 'modification', 'elimination') NOT NULL,
    ticket VARCHAR(255),
    description TEXT NOT NULL,
    rule_content TEXT NOT NULL,
    modified_by VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_rule_name (rule_name),
    INDEX idx_created_at (created_at),
    INDEX idx_tuning_driver (tuning_driver),
    INDEX idx_action_type (action_type)
);