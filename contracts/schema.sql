-- ==============================================================================
-- REFERENCIA PARA DESPLIEGUES FUTUROS, NO USADO EN ESTA VERSIÓN.
-- El backend actual solo usa SQLite (node:sqlite) con el esquema de
-- backend/migrations/001_esquema.sql (copiado en contracts/schema.sqlite.sql).
-- Este archivo traduce ese esquema a PostgreSQL 16 con las mismas 8 tablas y las
-- mismas columnas, en el mismo orden, por si en el futuro se escribe un adaptador
-- de persistencia para PostgreSQL. No existe hoy ningún adaptador ni dependencia pg.
-- Diferencias de tipo respecto a SQLite (mismos nombres de columna):
--   * UUID / TIMESTAMPTZ / BOOLEAN / JSONB nativos en lugar de TEXT / INTEGER 0-1.
--   * Material cifrado (seed_*, private_*) en TEXT base64, igual que en SQLite,
--     para que un adaptador futuro pueda reutilizar el formato de los repositorios.
--   * En SQLite los identificadores los genera la aplicación (randomUUID);
--     aquí se deja además un DEFAULT gen_random_uuid().
-- Alineado con el código el 26-11-2026.
-- ==============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 1. Aplicaciones integradoras (Portal de Trámites, Reto 3, Consola Admin, etc.)
CREATE TABLE IF NOT EXISTS apps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nombre VARCHAR(120) NOT NULL,
    client_id VARCHAR(80) UNIQUE NOT NULL,
    secret_hash TEXT NOT NULL,                     -- scrypt hash del client_secret
    algoritmo VARCHAR(10) NOT NULL DEFAULT 'SHA256' CHECK (algoritmo IN ('SHA256', 'SHA512', 'SHA1')),
    digitos INT NOT NULL DEFAULT 6 CHECK (digitos IN (6, 8)),
    periodo INT NOT NULL DEFAULT 30 CHECK (periodo BETWEEN 15 AND 60),
    ventana INT NOT NULL DEFAULT 1 CHECK (ventana BETWEEN 0 AND 3),
    max_intentos INT NOT NULL DEFAULT 5 CHECK (max_intentos BETWEEN 3 AND 15),
    umbral_riesgo_bloqueo REAL NOT NULL DEFAULT 75.0 CHECK (umbral_riesgo_bloqueo BETWEEN 40.0 AND 100.0),
    modo_heuristica VARCHAR(15) NOT NULL DEFAULT 'bloqueo' CHECK (modo_heuristica IN ('monitorizacion', 'bloqueo')),
    permitir_sha1 BOOLEAN NOT NULL DEFAULT FALSE,
    estado VARCHAR(20) NOT NULL DEFAULT 'activo' CHECK (estado IN ('activo', 'suspendido')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Enrolamientos TOTP (semillas cifradas AES-256-GCM con AAD = id || ':' || key_version)
CREATE TABLE IF NOT EXISTS enrollments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id UUID NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    user_ref_hash VARCHAR(64) NOT NULL,            -- HMAC-SHA256(user_ref, USER_REF_PEPPER); cero PII
    estado VARCHAR(20) NOT NULL DEFAULT 'pendiente' CHECK (estado IN ('pendiente', 'activo', 'suspendido', 'revocado')),
    algoritmo VARCHAR(10) NOT NULL CHECK (algoritmo IN ('SHA256', 'SHA512', 'SHA1')),
    digitos INT NOT NULL CHECK (digitos IN (6, 8)),
    periodo INT NOT NULL DEFAULT 30,
    seed_ct TEXT NOT NULL,                         -- base64 AES-256-GCM ciphertext
    seed_nonce TEXT NOT NULL,                      -- base64 96-bit nonce
    seed_auth_tag TEXT NOT NULL,                   -- base64 128-bit GCM auth tag
    key_version VARCHAR(20) NOT NULL DEFAULT 'v1',
    drift_steps INT NOT NULL DEFAULT 0,
    last_step BIGINT NOT NULL DEFAULT -1,          -- Anti-replay atómico: exigir T > last_step
    failed_attempts INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    pending_expires_at TIMESTAMPTZ,                -- Caduca a los 10 minutos si no se activa
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    activated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_enrollments_app_user ON enrollments(app_id, user_ref_hash);

-- 3. Códigos de recuperación de un solo uso (10 al activar, guardados con scrypt)
CREATE TABLE IF NOT EXISTS recovery_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    enrollment_id UUID NOT NULL REFERENCES enrollments(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_recovery_enrollment ON recovery_codes(enrollment_id);

-- 4. Intentos de verificación (alimenta rate limit e IA local; purga a los 30 días)
CREATE TABLE IF NOT EXISTS attempts (
    id BIGSERIAL PRIMARY KEY,
    enrollment_id UUID REFERENCES enrollments(id) ON DELETE SET NULL,
    app_id UUID REFERENCES apps(id) ON DELETE SET NULL,
    user_ref_hash VARCHAR(64),
    ip_hash VARCHAR(64) NOT NULL,                  -- HMAC-SHA256 con pepper rotativo diario
    resultado VARCHAR(30) NOT NULL,                -- ok, invalid_code, replay, locked, anomaly_blocked
    risk_score REAL,
    reasons_json JSONB,
    inference_ms REAL,
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_attempts_ts ON attempts(ts DESC);
CREATE INDEX IF NOT EXISTS idx_attempts_ip_ts ON attempts(ip_hash, ts DESC);
CREATE INDEX IF NOT EXISTS idx_attempts_user_ts ON attempts(user_ref_hash, ts DESC);

-- 5. JTIs de JWT consumidos (evita replay de comprobantes MFA)
CREATE TABLE IF NOT EXISTS consumed_jti (
    jti UUID PRIMARY KEY,
    expira_en TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_consumed_jti_exp ON consumed_jti(expira_en);

-- 6. Claves asimétricas locales Ed25519 (rotación por kid)
CREATE TABLE IF NOT EXISTS signing_keys (
    kid VARCHAR(64) PRIMARY KEY,
    public_jwk JSONB NOT NULL,
    private_ct TEXT NOT NULL,                      -- base64: privada Ed25519 cifrada con AES-256-GCM (AAD 'signing:'+kid)
    private_nonce TEXT NOT NULL,
    private_auth_tag TEXT NOT NULL,
    key_version VARCHAR(20) NOT NULL DEFAULT 'v1',
    estado VARCHAR(20) NOT NULL CHECK (estado IN ('activa', 'solo_verificacion', 'retirada')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at TIMESTAMPTZ
);

-- 7. Administradores de la Consola (RBAC + TOTP propio)
CREATE TABLE IF NOT EXISTS admins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    usuario VARCHAR(80) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,                   -- scrypt hash
    rol VARCHAR(20) NOT NULL CHECK (rol IN ('Administrador', 'Operador', 'Auditor')),
    totp_enrollment_id UUID REFERENCES enrollments(id) ON DELETE SET NULL,
    activo BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 8. Bitácora encadenada por hashes (a prueba de manipulación)
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor VARCHAR(120) NOT NULL,
    accion VARCHAR(80) NOT NULL,
    objetivo VARCHAR(160),
    detalle JSONB,
    prev_hash VARCHAR(64) NOT NULL,
    hash VARCHAR(64) NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
