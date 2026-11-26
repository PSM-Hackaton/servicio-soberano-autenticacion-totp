// Rotación de la llave maestra sobre una base SQLite temporal en disco: recifrado en lote,
// idempotencia, abortar sin cambios si falta la llave anterior y el script de operador.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { abrirBaseDatos } from './db.js';
import { crearRepositorios } from './repositorios.js';
import { recifrarConLlaveActiva, ErrorRotacion } from './rotacionLlaveMaestra.js';
import { crearVault } from '../../core/vault/vault.js';
import { crearFirmas } from '../config/firmas.js';
import { crearBitacora, verificarCadena } from '../../audit/index.js';

const SCRIPT = fileURLToPath(new URL('../../../scripts/rotar-llave-maestra.js', import.meta.url));
const V1 = randomBytes(32);
const V2 = randomBytes(32);

/** Base temporal con 3 semillas y 2 claves de firma cifradas con v1. */
function prepararBase(carpeta) {
  const ruta = join(carpeta, 'totp.db');
  const db = abrirBaseDatos(ruta);
  const repos = crearRepositorios(db);
  const vault = crearVault({ llaves: { v1: V1 }, versionActiva: 'v1' });
  const app = repos.apps.crear({ nombre: 'Portal', client_id: 'portal', secret_hash: 'scrypt$x' });
  const semillas = new Map();
  for (let i = 0; i < 3; i++) {
    const id = `00000000-0000-4000-8000-00000000000${i}`;
    const semilla = randomBytes(32);
    const c = vault.encryptSeed(semilla, id);
    repos.enrollments.crearPendiente({
      id, app_id: app.id, user_ref_hash: String(i).repeat(64), algoritmo: 'SHA256', digitos: 6, periodo: 30,
      seed_ct: c.ct, seed_nonce: c.nonce, seed_auth_tag: c.authTag, key_version: c.keyVersion,
    });
    semillas.set(id, semilla);
  }
  const firmas = crearFirmas({ repos, vault }).recargar();
  firmas.rotar(); // dos claves: la activa y una en solo_verificacion
  db.close();
  return { ruta, semillas };
}

function abrir(ruta, llaves, versionActiva) {
  const db = abrirBaseDatos(ruta);
  const repos = crearRepositorios(db);
  const vault = crearVault({ llaves, versionActiva });
  const bitacora = crearBitacora({ ultimo: () => repos.auditLog.ultimo(), insertar: (f) => repos.auditLog.insertar(f).id });
  return { db, repos, vault, bitacora };
}

const versiones = (db, tabla) => db.prepare(`SELECT key_version AS v, COUNT(*) AS n FROM ${tabla} GROUP BY key_version`).all()
  .map((f) => `${f.v}:${f.n}`).join(',');

describe('rotación de la llave maestra', () => {
  test('recifra en lote semillas y claves de firma, es idempotente y deja todo descifrable con v2', () => {
    const carpeta = mkdtempSync(join(tmpdir(), 'rotacion-'));
    try {
      const { ruta, semillas } = prepararBase(carpeta);
      const e = abrir(ruta, { v1: V1, v2: V2 }, 'v2');
      try {
        const r = recifrarConLlaveActiva(e);
        assert.deepEqual(r, { versionActiva: 'v2', semillas: 3, clavesFirma: 2 });
        assert.equal(versiones(e.db, 'enrollments'), 'v2:3');
        assert.equal(versiones(e.db, 'signing_keys'), 'v2:2');

        const segunda = recifrarConLlaveActiva(e);
        assert.deepEqual(segunda, { versionActiva: 'v2', semillas: 0, clavesFirma: 0 }, 'idempotente');

        const eventos = [...e.repos.auditLog.recorrerTodo()];
        assert.equal(eventos.filter((f) => f.accion === 'llave_maestra.rotada').length, 1);
        assert.equal(verificarCadena(eventos).intact, true);
      } finally {
        e.db.close();
      }

      // Sin la llave v1 todo sigue funcionando: la v2 basta.
      const solo2 = abrir(ruta, { v2: V2 }, 'v2');
      try {
        for (const [id, semilla] of semillas) {
          const f = solo2.repos.enrollments.buscarPorId(id);
          const claro = solo2.vault.decryptSeed({ ct: f.seed_ct, nonce: f.seed_nonce, authTag: f.seed_auth_tag, keyVersion: f.key_version }, id);
          assert.ok(claro.equals(semilla));
        }
        const firmas = crearFirmas({ repos: solo2.repos, vault: solo2.vault }).recargar();
        assert.ok(firmas.activa().privateKey);
      } finally {
        solo2.db.close();
      }
    } finally {
      rmSync(carpeta, { recursive: true, force: true });
    }
  });

  test('si falta la llave anterior se aborta sin modificar nada', () => {
    const carpeta = mkdtempSync(join(tmpdir(), 'rotacion-'));
    try {
      const { ruta } = prepararBase(carpeta);
      const e = abrir(ruta, { v2: V2 }, 'v2');
      try {
        assert.throws(() => recifrarConLlaveActiva(e), (err) => err instanceof ErrorRotacion && /v1/.test(err.message));
        assert.equal(versiones(e.db, 'enrollments'), 'v1:3');
        assert.equal(versiones(e.db, 'signing_keys'), 'v1:2');
      } finally {
        e.db.close();
      }
    } finally {
      rmSync(carpeta, { recursive: true, force: true });
    }
  });

  test('un registro alterado aborta toda la transacción (ningún registro queda a medias)', () => {
    const carpeta = mkdtempSync(join(tmpdir(), 'rotacion-'));
    try {
      const { ruta } = prepararBase(carpeta);
      const e = abrir(ruta, { v1: V1, v2: V2 }, 'v2');
      try {
        e.db.prepare("UPDATE enrollments SET seed_auth_tag = ? WHERE id LIKE '%2'").run(randomBytes(16).toString('base64'));
        assert.throws(() => recifrarConLlaveActiva(e), ErrorRotacion);
        assert.equal(versiones(e.db, 'enrollments'), 'v1:3');
        assert.equal(versiones(e.db, 'signing_keys'), 'v1:2');
      } finally {
        e.db.close();
      }
    } finally {
      rmSync(carpeta, { recursive: true, force: true });
    }
  });

  test('script npm run rotar-llave-maestra con ENV_FILE temporal: informa conteos y es idempotente', () => {
    const carpeta = mkdtempSync(join(tmpdir(), 'rotacion-'));
    try {
      const { ruta } = prepararBase(carpeta);
      const env = join(carpeta, '.env');
      writeFileSync(env, [
        'TLS_MODE=off', `SQLITE_DB_PATH=${ruta}`, 'MASTER_KEY_VERSION=v2',
        `MASTER_KEY_V1_HEX=${V1.toString('hex')}`, `MASTER_KEY_V2_HEX=${V2.toString('hex')}`,
        `USER_REF_PEPPER=${'p'.repeat(43)}`, `DAILY_IP_PEPPER_SEED=${'q'.repeat(43)}`,
      ].join('\n'));
      const ejecutar = () => execFileSync(process.execPath, [SCRIPT], { env: { PATH: process.env.PATH, ENV_FILE: env }, encoding: 'utf8' });
      const primera = ejecutar();
      assert.match(primera, /Semillas recifradas:\s+3/);
      assert.match(primera, /Claves privadas de firma recifradas:\s+2/);
      const segunda = ejecutar();
      assert.match(segunda, /Semillas recifradas:\s+0/);
      assert.match(segunda, /Nada que rotar/);
      assert.doesNotMatch(primera + segunda, new RegExp(V1.toString('hex')));
    } finally {
      rmSync(carpeta, { recursive: true, force: true });
    }
  });
});
