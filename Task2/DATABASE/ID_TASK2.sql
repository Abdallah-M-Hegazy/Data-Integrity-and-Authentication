CREATE DATABASE ID_TASK2;
USE ID_TASK2;

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    auth_method VARCHAR(10) NOT NULL CHECK (auth_method IN ('manual', 'github')),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE manual_auth (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL
);

CREATE TABLE github_auth (
    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    github_id VARCHAR(50) UNIQUE NOT NULL,
    github_username VARCHAR(50),
    github_email VARCHAR(255)
);

CREATE TABLE login_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    login_timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT
);

CREATE TABLE failed_login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    identifier VARCHAR(255) NOT NULL,
    attempts INT DEFAULT 0,
    blocked_until TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE `failed_login_attempts` (
    id INT AUTO_INCREMENT PRIMARY KEY,
    identifier VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    attempt_time DATETIME NOT NULL
);

CREATE INDEX idx_failed_attempts_identifier ON `failed_login_attempts` (identifier);
CREATE INDEX idx_failed_attempts_time ON `failed_login_attempts` (attempt_time);

ALTER TABLE users ADD COLUMN twofa_enabled BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users ADD COLUMN twofa_secret VARCHAR(32);
ALTER TABLE login_logs ADD COLUMN auth_method VARCHAR(10) NOT NULL DEFAULT 'manual';
ALTER TABLE login_logs ADD COLUMN twofa_used BOOLEAN NOT NULL DEFAULT FALSE;

