// Conexión SQLite nativa (node:sqlite) y aplicación de migraciones.
// Sin dependencias externas: solo módulos incluidos en Node.js 22.

import { DatabaseSync } from 'node:sqlite';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Carpeta de migraciones, resuelta respecto a este archivo (no al directorio de trabajo). */
export const CARPETA_MIGRACIONES = fileURLToPath(new URL('../../../migrations/', import.meta.url));

/**
 * Abre (o crea) la base de datos, configura los PRAGMA y aplica las migraciones pendientes.
 * @param {string} ruta Ruta del archivo SQLite o ':memory:'.
 * @param {{ carpetaMigraciones?: string }} [opciones]
 * @returns {DatabaseSync}
 */
export function abrirBaseDatos(ruta, opciones = {}) {
  const db = new DatabaseSync(ruta);
  // WAL no aplica a bases en memoria (SQLite responde 'memory' y lo ignora).
  if (ruta !== ':memory:') db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec('PRAGMA busy_timeout = 5000;');
  aplicarMigraciones(db, opciones.carpetaMigraciones ?? CARPETA_MIGRACIONES);
  return db;
}

/**
 * Aplica en orden alfabético los *.sql aún no registrados en schema_migrations.
 * Cada migración corre en su propia transacción: o se aplica entera o no se aplica.
 * Es idempotente: abrir la misma base dos veces no vuelve a ejecutar nada.
 * @param {DatabaseSync} db
 * @param {string} carpeta
 * @returns {string[]} Versiones aplicadas en esta llamada.
 */
export function aplicarMigraciones(db, carpeta) {
  db.exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    aplicada_en TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
  );`);
  const aplicadas = new Set(db.prepare('SELECT version FROM schema_migrations').all().map((f) => f.version));
  const registrar = db.prepare('INSERT INTO schema_migrations (version) VALUES (?)');
  const archivos = readdirSync(carpeta).filter((a) => a.endsWith('.sql')).sort();
  const nuevas = [];
  for (const archivo of archivos) {
    if (aplicadas.has(archivo)) continue;
    const sql = readFileSync(join(carpeta, archivo), 'utf8');
    db.exec('BEGIN IMMEDIATE');
    try {
      db.exec(sql);
      registrar.run(archivo);
      db.exec('COMMIT');
    } catch (error) {
      db.exec('ROLLBACK');
      throw new Error(`Fallo al aplicar la migración ${archivo}: ${error.message}`, { cause: error });
    }
    nuevas.push(archivo);
  }
  return nuevas;
}
