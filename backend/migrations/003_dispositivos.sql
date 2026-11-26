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
