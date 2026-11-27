-- ==============================================================================
-- Migración 003: índices de cobertura para el historial del detector de anomalías.
--   Cada verificación lee hasta 100 intentos recientes (50 por origen y 50 por cuenta) con solo
--   id, user_ref_hash, ip_hash, resultado y ts. Con estos índices la consulta se resuelve solo con
--   el índice (COVERING INDEX), sin leer la fila completa de attempts (ni reasons_json).
--   Sustituyen a idx_attempts_ip_ts e idx_attempts_user_ts (mismas columnas iniciales, por lo que
--   también sirven a los conteos de fallos y al bloqueo de cuentas inexistentes): el número de
--   índices que se actualizan en cada inserción no cambia. `id DESC` (alias de rowid) evita el
--   ordenamiento temporal (TEMP B-TREE) del desempate ORDER BY ts DESC, id DESC.
-- ==============================================================================

DROP INDEX IF EXISTS idx_attempts_ip_ts;
DROP INDEX IF EXISTS idx_attempts_user_ts;
CREATE INDEX IF NOT EXISTS idx_attempts_ip_ts_det ON attempts(ip_hash, ts DESC, id DESC, resultado, user_ref_hash);
CREATE INDEX IF NOT EXISTS idx_attempts_user_ts_det ON attempts(user_ref_hash, ts DESC, id DESC, resultado, ip_hash);
