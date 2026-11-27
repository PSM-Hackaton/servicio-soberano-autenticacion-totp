// Conexión SQLite nativa (node:sqlite) y aplicación de migraciones.
// Sin dependencias externas: solo módulos incluidos en Node.js 22.

import { DatabaseSync } from 'node:sqlite';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Carpeta de migraciones, resuelta respecto a este archivo (no al directorio de trabajo). */
export const CARPETA_MIGRACIONES = fileURLToPath(new URL('../../../migrations/', import.meta.url));

/** Modos admitidos de PRAGMA synchronous (SQLITE_SYNCHRONOUS). */
export const MODOS_SINCRONO = Object.freeze(['FULL', 'NORMAL']);

/**
 * Modo de confirmación a disco por defecto: NORMAL en WAL.
 * Compromiso (https://www.sqlite.org/pragma.html#pragma_synchronous): en modo WAL, NORMAL no
 * sincroniza el WAL en cada COMMIT sino en cada checkpoint. La base NUNCA se corrompe y una caída
 * del PROCESO no pierde nada (el WAL ya está en el sistema operativo); solo un corte de energía o
 * una caída del sistema operativo puede deshacer las últimas transacciones confirmadas antes del
 * siguiente checkpoint. En este servicio eso equivale, como mucho, a perder los últimos intentos,
 * eventos de bitácora o pasos aceptados de ese instante (un código ya usado podría volver a valer
 * dentro de su ventana de 30 s tras el corte). FULL elimina esa ventana a cambio de un fsync por
 * transacción (×3 a ×5 menos verificaciones por segundo medidas: docs/escalabilidad).
 */
export const SINCRONO_POR_DEFECTO = 'NORMAL';

/**
 * Abre (o crea) la base de datos, configura los PRAGMA y aplica las migraciones pendientes.
 * @param {string} ruta Ruta del archivo SQLite o ':memory:'.
 * @param {{ carpetaMigraciones?: string, sincrono?: 'FULL' | 'NORMAL' }} [opciones]
 * @returns {DatabaseSync}
 */
export function abrirBaseDatos(ruta, opciones = {}) {
  const sincrono = opciones.sincrono ?? SINCRONO_POR_DEFECTO;
  if (!MODOS_SINCRONO.includes(sincrono)) throw new TypeError(`Modo synchronous no admitido: ${sincrono}`);
  const db = new DatabaseSync(ruta);
  // WAL no aplica a bases en memoria (SQLite responde 'memory' y lo ignora).
  if (ruta !== ':memory:') db.exec('PRAGMA journal_mode = WAL;');
  db.exec(`PRAGMA synchronous = ${sincrono};`);
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
