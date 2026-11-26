-- ==============================================================================
-- CONTRATO: esquema SQLite del Servicio Soberano TOTP (base de datos de esta versión).
-- Copia exacta de backend/migrations/001_esquema.sql seguida de 002_cedula_apps.sql y 003_dispositivos.sql,
-- que son la fuente de verdad: el backend aplica las migraciones al abrir la base (node:sqlite, modo WAL y
-- foreign_keys activados por backend/src/infrastructure/persistence/db.js).
-- Si cambia una migración, este archivo se regenera copiándolas tal cual y en orden.
-- Alineado con el código el 26-11-2026.
-- ==============================================================================

-- ==============================================================================
-- Migración 001: esquema inicial SQLite (8 tablas de contracts/schema.sqlite.sql).
-- Copia fiel del contrato con estos ajustes, documentados aquí:
--   1. Se quitan los PRAGMA (journal_mode, foreign_keys): no tienen efecto dentro
--      de la transacción de la migración; los activa db.js al abrir la conexión.
--   2. Se añaden los índices que el esquema PostgreSQL define y el SQLite omite:
--      idx_recovery_enrollment, idx_attempts_user_ts, idx_consumed_jti_exp, idx_audit_ts.
-- Las semillas y claves privadas cifradas se guardan como TEXT base64, tal como
-- define el contrato; el repositorio expone siempre Buffer hacia fuera.
-- Fechas: texto ISO 8601 UTC con milisegundos (mismo formato que toISOString()).
-- ==============================================================================

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

-- Ajuste 2: índice presente en contracts/schema.sql
CREATE INDEX IF NOT EXISTS idx_recovery_enrollment ON recovery_codes(enrollment_id);

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
-- Ajuste 2: índice presente en contracts/schema.sql
CREATE INDEX IF NOT EXISTS idx_attempts_user_ts ON attempts(user_ref_hash, ts DESC);

CREATE TABLE IF NOT EXISTS consumed_jti (
    jti TEXT PRIMARY KEY,
    expira_en TEXT NOT NULL
);

-- Ajuste 2: índice presente en contracts/schema.sql
CREATE INDEX IF NOT EXISTS idx_consumed_jti_exp ON consumed_jti(expira_en);

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

-- Ajuste 2: índice presente en contracts/schema.sql
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);

-- ==============================================================================
-- Migración 002: derivación del user_ref desde la cédula de identidad (opcional por app).
--   user_ref_desde_cedula = 'ninguno' (por defecto): el user_ref es opaco y el servicio no sabe
--     nada de la cédula; la búsqueda de soporte solo admite user_ref exacto.
--   user_ref_desde_cedula = 'hmac': la app deriva user_ref = cedula_prefijo +
--     base64url(HMAC-SHA256(cédula canónica, secreto de derivación)). El secreto se guarda
--     cifrado con la bóveda (AES-256-GCM, AAD = 'cedula:' + app_id + ':' + key_version) y solo se
--     usa para recalcular el user_ref en la búsqueda por cédula desde la consola.
-- La cédula nunca se guarda en claro: ni aquí ni en la bitácora (allí solo su HMAC con pepper).
-- ==============================================================================

ALTER TABLE apps ADD COLUMN user_ref_desde_cedula TEXT NOT NULL DEFAULT 'ninguno'
    CHECK (user_ref_desde_cedula IN ('ninguno', 'hmac'));
ALTER TABLE apps ADD COLUMN cedula_prefijo TEXT NOT NULL DEFAULT '';
ALTER TABLE apps ADD COLUMN cedula_secreto_ct TEXT;          -- base64 AES-256-GCM ciphertext
ALTER TABLE apps ADD COLUMN cedula_secreto_nonce TEXT;       -- base64 96-bit nonce
ALTER TABLE apps ADD COLUMN cedula_secreto_auth_tag TEXT;    -- base64 128-bit GCM auth tag
ALTER TABLE apps ADD COLUMN cedula_key_version TEXT;

-- ==============================================================================
-- Migración 003: vinculación de dispositivos (issue #47, M8).
-- Cada enrolamiento puede quedar asociado a UN dispositivo (la app móvil Android, la PWA u otro
-- autenticador estándar) para que el integrador y la consola puedan consultarlo y revocarlo.
--   id          seudónimo aleatorio 'dev_' + 22 caracteres base64url (128 bits). No deriva de
--               ningún identificador de hardware (IMEI, MAC, Android ID…): no se recogen.
--   nombre      nombre visible que elige el usuario ("Teléfono de trabajo"), ya saneado por el
--               caso de uso (sin controles ni caracteres invisibles, espacios colapsados, ≤ 64).
--   plataforma  'android' | 'pwa' | 'otro'.
--   created_at  alta (al crear el enrolamiento pendiente).
--   ultimo_uso  último código aceptado (activación o verificación); NULL si nunca se usó.
--   desvinculado_en  fecha de desvinculación explícita (DELETE /api/v1/enrollments/{id}/device).
-- Sin datos personales: el nombre lo escribe el usuario y la consola recomienda no usar su nombre.
-- Al borrar el enrolamiento se borra el dispositivo (ON DELETE CASCADE).
-- ==============================================================================

CREATE TABLE IF NOT EXISTS dispositivos (
    id TEXT PRIMARY KEY CHECK (id GLOB 'dev_*' AND length(id) = 26),
    enrollment_id TEXT UNIQUE NOT NULL REFERENCES enrollments(id) ON DELETE CASCADE,
    nombre TEXT NOT NULL CHECK (length(nombre) BETWEEN 1 AND 64),
    plataforma TEXT NOT NULL DEFAULT 'otro' CHECK (plataforma IN ('android', 'pwa', 'otro')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    ultimo_uso TEXT,
    desvinculado_en TEXT
);
