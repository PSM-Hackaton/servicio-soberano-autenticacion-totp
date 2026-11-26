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
