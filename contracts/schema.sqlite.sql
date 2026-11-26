-- ==============================================================================
-- Esquema Fallback SQLite WAL (Mismas 8 tablas exactas de PostgreSQL 16)
-- Permite desarrollar y ejecutar tests 100% locales en estaciones SIN Docker.
-- ==============================================================================

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS apps (
    id TEXT PRIMARY KEY,
    nombre TEXT NOT NULL,
    client_id TEXT UNIQUE NOT NULL,
    secret_hash TEXT NOT NULL,
    algoritmo TEXT NOT NULL DEFAULT 'SHA256' CHECK (algoritmo IN ('SHA256', 'SHA512', 'SHA1')),
    digitos INTEGER NOT NULL DEFAULT 6 CHECK (digitos IN (6, 8)),
    periodo INTEGER NOT NULL DEFAULT 30 CHECK (periodo BETWEEN 15 AND 60),
    ventana INTEGER NOT NULL DEFAULT 1 CHECK (ventana BETWEEN 0 AND 3),
    max_intentos INTEGER NOT NULL DEFAULT 5 CHECK (max_intentos BETWEEN 3 AND 15),
    umbral_riesgo_bloqueo REAL NOT NULL DEFAULT 75.0 CHECK (umbral_riesgo_bloqueo BETWEEN 40.0 AND 100.0),
    modo_heuristica TEXT NOT NULL DEFAULT 'bloqueo' CHECK (modo_heuristica IN ('monitorizacion', 'bloqueo')),
    permitir_sha1 INTEGER NOT NULL DEFAULT 0,
    estado TEXT NOT NULL DEFAULT 'activo' CHECK (estado IN ('activo', 'suspendido')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS enrollments (
    id TEXT PRIMARY KEY,
    app_id TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    user_ref_hash TEXT NOT NULL,
    estado TEXT NOT NULL DEFAULT 'pendiente' CHECK (estado IN ('pendiente', 'activo', 'suspendido', 'revocado')),
    algoritmo TEXT NOT NULL CHECK (algoritmo IN ('SHA256', 'SHA512', 'SHA1')),
    digitos INTEGER NOT NULL CHECK (digitos IN (6, 8)),
    periodo INTEGER NOT NULL DEFAULT 30,
    seed_ct TEXT NOT NULL,                         -- base64 AES-256-GCM ciphertext
    seed_nonce TEXT NOT NULL,                      -- base64 96-bit nonce
    seed_auth_tag TEXT NOT NULL,                   -- base64 128-bit GCM auth tag
    key_version TEXT NOT NULL DEFAULT 'v1',
    drift_steps INTEGER NOT NULL DEFAULT 0,
    last_step INTEGER NOT NULL DEFAULT -1,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    pending_expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    activated_at TEXT,
    revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_enrollments_app_user ON enrollments(app_id, user_ref_hash);

CREATE TABLE IF NOT EXISTS recovery_codes (
    id TEXT PRIMARY KEY,
    enrollment_id TEXT NOT NULL REFERENCES enrollments(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at TEXT
);

CREATE TABLE IF NOT EXISTS attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    enrollment_id TEXT REFERENCES enrollments(id) ON DELETE SET NULL,
    app_id TEXT REFERENCES apps(id) ON DELETE SET NULL,
    user_ref_hash TEXT,
    ip_hash TEXT NOT NULL,
    resultado TEXT NOT NULL,
    risk_score REAL,
    reasons_json TEXT,
    inference_ms REAL,
    ts TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_attempts_ts ON attempts(ts DESC);
CREATE INDEX IF NOT EXISTS idx_attempts_ip_ts ON attempts(ip_hash, ts DESC);

CREATE TABLE IF NOT EXISTS consumed_jti (
    jti TEXT PRIMARY KEY,
    expira_en TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS signing_keys (
    kid TEXT PRIMARY KEY,
    public_jwk TEXT NOT NULL,
    private_ct TEXT NOT NULL,
    private_nonce TEXT NOT NULL,
    private_auth_tag TEXT NOT NULL,
    key_version TEXT NOT NULL DEFAULT 'v1',
    estado TEXT NOT NULL CHECK (estado IN ('activa', 'solo_verificacion', 'retirada')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    rotated_at TEXT
);

CREATE TABLE IF NOT EXISTS admins (
    id TEXT PRIMARY KEY,
    usuario TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    rol TEXT NOT NULL CHECK (rol IN ('Administrador', 'Operador', 'Auditor')),
    totp_enrollment_id TEXT REFERENCES enrollments(id) ON DELETE SET NULL,
    activo INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    actor TEXT NOT NULL,
    accion TEXT NOT NULL,
    objetivo TEXT,
    detalle TEXT,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
