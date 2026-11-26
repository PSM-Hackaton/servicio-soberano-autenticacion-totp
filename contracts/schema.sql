-- ==============================================================================
-- Esquema SQL Congelado — Servicio Soberano MFA / TOTP (SQLite WAL)
-- Diseñado bajo Arquitectura Hexagonal: portátil a PostgreSQL sin tocar dominio.
-- TODA semilla criptográfica y clave privada se persiste cifrada con AES-256-GCM.
-- TODA dirección IP se persiste únicamente anonimizada vía HMAC-SHA256 local.
-- ==============================================================================

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- 1. Administradores de la Consola (RBAC)
CREATE TABLE IF NOT EXISTS admin_users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,            -- scrypt / argon2id con salt
    role TEXT NOT NULL CHECK (role IN ('ADMIN', 'AUDITOR')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- 2. Políticas Globales de Autenticación TOTP y Resiliencia
CREATE TABLE IF NOT EXISTS totp_policies (
    id INTEGER PRIMARY KEY CHECK (id = 1),  -- Singleton de política activa
    default_algorithm TEXT NOT NULL DEFAULT 'SHA256' CHECK (default_algorithm IN ('SHA256', 'SHA512', 'SHA1')),
    digits INTEGER NOT NULL DEFAULT 6 CHECK (digits IN (6, 8)),
    step_seconds INTEGER NOT NULL DEFAULT 30 CHECK (step_seconds BETWEEN 15 AND 60),
    drift_window INTEGER NOT NULL DEFAULT 1 CHECK (drift_window BETWEEN 0 AND 3),
    jwt_ttl_seconds INTEGER NOT NULL DEFAULT 300 CHECK (jwt_ttl_seconds BETWEEN 60 AND 3600),
    max_failed_attempts INTEGER NOT NULL DEFAULT 5 CHECK (max_failed_attempts BETWEEN 3 AND 15),
    lockout_minutes INTEGER NOT NULL DEFAULT 5 CHECK (lockout_minutes BETWEEN 1 AND 60),
    anomaly_block_threshold REAL NOT NULL DEFAULT 75.0 CHECK (anomaly_block_threshold BETWEEN 50.0 AND 100.0),
    updated_by TEXT,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- 3. Enrolamientos de Usuarios (Semillas cifradas en reposo con AES-256-GCM)
CREATE TABLE IF NOT EXISTS user_enrollments (
    id TEXT PRIMARY KEY,
    external_user_id TEXT UNIQUE NOT NULL,
    account_label TEXT NOT NULL,
    source_app TEXT NOT NULL DEFAULT 'portal-demo',
    algorithm TEXT NOT NULL CHECK (algorithm IN ('SHA256', 'SHA512', 'SHA1')),
    digits INTEGER NOT NULL CHECK (digits IN (6, 8)),
    step_seconds INTEGER NOT NULL,
    -- Semilla TOTP cifrada (NUNCA en texto plano)
    secret_ciphertext TEXT NOT NULL,
    secret_iv TEXT NOT NULL,
    secret_auth_tag TEXT NOT NULL,
    -- Estado y compensación de deriva temporal
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'LOCKED', 'REVOKED')),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    last_drift_steps INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_enrollments_external_id ON user_enrollments(external_user_id);

-- 4. Bóveda Local de Claves Asimétricas Ed25519 (JWT + JWKS con rotación kid)
CREATE TABLE IF NOT EXISTS signing_keys (
    kid TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL DEFAULT 'EdDSA',
    public_jwk_json TEXT NOT NULL,
    -- Clave privada Ed25519 cifrada con AES-256-GCM
    private_key_ciphertext TEXT NOT NULL,
    private_key_iv TEXT NOT NULL,
    private_key_auth_tag TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ACTIVE', 'VERIFY_ONLY', 'RETIRED')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    rotated_at TEXT
);

-- 5. Protección Anti-Replay (bloqueo temporal de códigos ya usados en ventana)
CREATE TABLE IF NOT EXISTS replay_guard (
    enrollment_id TEXT NOT NULL REFERENCES user_enrollments(id) ON DELETE CASCADE,
    time_step INTEGER NOT NULL,
    used_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at TEXT NOT NULL,
    PRIMARY KEY (enrollment_id, time_step)
);

CREATE INDEX IF NOT EXISTS idx_replay_expires ON replay_guard(expires_at);

-- 6. Bitácora de Auditoría Anonimizada (sin IPs en texto plano ni secretos)
CREATE TABLE IF NOT EXISTS auth_audit_events (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,               -- ENROLL, VERIFY_OK, VERIFY_FAIL, REPLAY_BLOCKED, ANOMALY_BLOCKED, KEY_ROTATED, USER_REVOKED, POLICY_UPDATED
    external_user_id TEXT,
    source_app TEXT,
    ip_hash TEXT NOT NULL,                  -- HMAC-SHA256(ip, IP_ANON_SALT)
    outcome TEXT NOT NULL,
    risk_score REAL,
    detail TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_created_at ON auth_audit_events(created_at DESC);

-- 7. Alertas del Motor de IA Heurística Local (0 telemetría externa)
CREATE TABLE IF NOT EXISTS anomaly_alerts (
    id TEXT PRIMARY KEY,
    external_user_id TEXT,
    ip_hash TEXT NOT NULL,
    risk_score REAL NOT NULL,
    level TEXT NOT NULL CHECK (level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    action TEXT NOT NULL CHECK (action IN ('ALLOW', 'WARN', 'BLOCK')),
    reasons_json TEXT NOT NULL,             -- JSON array de factores explicables
    inference_ms REAL NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_anomalies_created_at ON anomaly_alerts(created_at DESC);

-- Semilla inicial de política activa
INSERT OR IGNORE INTO totp_policies (
    id, default_algorithm, digits, step_seconds, drift_window,
    jwt_ttl_seconds, max_failed_attempts, lockout_minutes, anomaly_block_threshold, updated_by
) VALUES (
    1, 'SHA256', 6, 30, 1, 300, 5, 5, 75.0, 'system_seed'
);
