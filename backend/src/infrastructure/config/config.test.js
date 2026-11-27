// Pruebas de configuración: parser .env propio, validación tipada, rechazo de CHANGE_ME y llavero de firma.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  parsearEnv, validarConfig, cargarConfig, ErrorConfiguracion, configCasosDeUso, EMISOR_TOTP_POR_DEFECTO,
} from './config.js';
import { generarContenido } from '../../../scripts/generar-env.js';
import { crearFirmas } from './firmas.js';
import { abrirBaseDatos } from '../persistence/db.js';
import { crearRepositorios } from '../persistence/repositorios.js';
import { crearVault } from '../../core/vault/vault.js';
import { signMfaJwt, verifyMfaJwt } from '../../core/tokens/tokens.js';

const VALIDAS = Object.freeze({
  NODE_ENV: 'development',
  HOST: '127.0.0.1',
  PORT: '8443',
  TLS_MODE: 'node',
  TLS_CERT_PATH: './certs/localhost.crt',
  TLS_KEY_PATH: './certs/localhost.key',
  DB_DRIVER: 'sqlite',
  SQLITE_DB_PATH: './data/prueba.db',
  MASTER_KEY_VERSION: 'v1',
  MASTER_KEY_V1_HEX: 'ab'.repeat(32),
  USER_REF_PEPPER: 'p'.repeat(43),
  DAILY_IP_PEPPER_SEED: 'q'.repeat(43),
  TOTP_ISSUER: 'Emisor',
  JWT_ISSUER: 'https://totp.soberano.local',
  JWT_TTL_SECONDS: '300',
  HEURISTICS_MODE: 'local',
  CORS_ALLOWED_ORIGINS: 'https://localhost:5173, http://localhost:3000',
});

describe('parsearEnv', () => {
  test('claves, comentarios, export, comillas y comentarios en línea', () => {
    const v = parsearEnv([
      '﻿# comentario',
      '',
      'A=1',
      'export B = dos ',
      'C="con espacios # no es comentario"',
      "D='literal \\n'",
      'E="salto\\nlinea"',
      'F=valor # comentario',
      'G=sin#comentario',
      'H=',
      'URL=postgres://u:p@h:5432/db?x=1',
    ].join('\r\n'));
    assert.equal(v.A, '1');
    assert.equal(v.B, 'dos');
    assert.equal(v.C, 'con espacios # no es comentario');
    assert.equal(v.D, 'literal \\n');
    assert.equal(v.E, 'salto\nlinea');
    assert.equal(v.F, 'valor');
    assert.equal(v.G, 'sin#comentario');
    assert.equal(v.H, '');
    assert.equal(v.URL, 'postgres://u:p@h:5432/db?x=1');
  });

  test('errores claros con número de línea', () => {
    assert.throws(() => parsearEnv('A=1\nSIN_IGUAL'), /línea 2/);
    assert.throws(() => parsearEnv('1A=x'), /nombre de variable/);
    assert.throws(() => parsearEnv('A="abierta'), /comilla sin cerrar/);
  });

  test('el .env de ejemplo del repositorio se interpreta', async () => {
    const { readFileSync } = await import('node:fs');
    const v = parsearEnv(readFileSync(new URL('../../../../.env.example', import.meta.url), 'utf8'));
    assert.equal(v.PORT, '8443');
    assert.match(v.MASTER_KEY_V1_HEX, /CHANGE_ME/);
  });
});

describe('validarConfig', () => {
  test('produce configuración tipada', () => {
    const c = validarConfig({ ...VALIDAS }, { base: '/srv/backend' });
    assert.equal(c.puerto, 8443);
    assert.equal(c.host, '127.0.0.1');
    assert.equal(c.tls.modo, 'node');
    assert.equal(c.tls.cert, '/srv/backend/certs/localhost.crt');
    assert.equal(c.baseDatos.ruta, '/srv/backend/data/prueba.db');
    assert.equal(c.vault.versionActiva, 'v1');
    assert.equal(c.vault.llaves.v1.length, 32);
    assert.equal(c.ttlJwtSegundos, 300);
    assert.deepEqual([...c.corsOrigenes], ['https://localhost:5173', 'http://localhost:3000']);
    assert.deepEqual(configCasosDeUso(c), {
      userRefPepper: VALIDAS.USER_REF_PEPPER, ipPepperSemilla: VALIDAS.DAILY_IP_PEPPER_SEED, emisorTotp: 'Emisor',
      emisorJwt: 'https://totp.soberano.local', ttlJwtSegundos: 300, minutosPendiente: 10, modoHeuristica: 'local',
      ventanaInexistentesMin: 1440,
    });
    assert.equal(c.admin.rutaQr, '/srv/backend/data/admin-qr.svg', 'el QR va junto a la base de datos');
  });

  test('límites de tasa: valores por defecto altos, configurables y validados', () => {
    const base = { base: '/srv/backend' };
    const d = validarConfig(VALIDAS, base);
    assert.deepEqual({ ...d.limites }, { globalPorMin: 6000, appPorMin: 3000, origenPorMin: 60 });
    const c = validarConfig({
      ...VALIDAS, RATE_LIMIT_GLOBAL_POR_MIN: '20000', RATE_LIMIT_APP_POR_MIN: '9000', RATE_LIMIT_ORIGEN_POR_MIN: '30',
      BLOQUEO_INEXISTENTES_VENTANA_MIN: '60',
    }, base);
    assert.deepEqual({ ...c.limites }, { globalPorMin: 20000, appPorMin: 9000, origenPorMin: 30 });
    assert.equal(configCasosDeUso(c).ventanaInexistentesMin, 60);
    assert.throws(() => validarConfig({ ...VALIDAS, RATE_LIMIT_GLOBAL_POR_MIN: '10' }, base), /RATE_LIMIT_GLOBAL_POR_MIN debe estar entre/);
    assert.throws(() => validarConfig({ ...VALIDAS, RATE_LIMIT_ORIGEN_POR_MIN: 'mucho' }, base), /RATE_LIMIT_ORIGEN_POR_MIN debe ser un entero/);
    assert.throws(() => validarConfig({ ...VALIDAS, BLOQUEO_INEXISTENTES_VENTANA_MIN: '0' }, base), /BLOQUEO_INEXISTENTES_VENTANA_MIN/);
  });

  test('ruta del QR del admin: junto a SQLITE_DB_PATH o ADMIN_QR_PATH', () => {
    const base = { base: '/srv/backend' };
    assert.equal(validarConfig({ ...VALIDAS, SQLITE_DB_PATH: '/var/lib/totp/datos.db' }, base).admin.rutaQr, '/var/lib/totp/admin-qr.svg');
    assert.equal(validarConfig({ ...VALIDAS, ADMIN_QR_PATH: './seguro/qr.svg' }, base).admin.rutaQr, '/srv/backend/seguro/qr.svg');
    assert.equal(validarConfig({ ...VALIDAS, SQLITE_DB_PATH: ':memory:' }, base).admin.rutaQr, '/srv/backend/data/admin-qr.svg');
  });

  test('emisor TOTP por defecto neutro y modo de heurística propagado', () => {
    const { TOTP_ISSUER: _e, ...sinEmisor } = VALIDAS;
    const c = validarConfig({ ...sinEmisor, HEURISTICS_MODE: 'monitorizacion' });
    assert.equal(c.emisorTotp, EMISOR_TOTP_POR_DEFECTO);
    assert.equal(EMISOR_TOTP_POR_DEFECTO, 'ServicioSoberanoTOTP');
    assert.equal(configCasosDeUso(c).modoHeuristica, 'monitorizacion');
  });

  test('rechaza valores CHANGE_ME (incluida la llave maestra)', () => {
    const e = assert.throws(() => validarConfig({
      ...VALIDAS, USER_REF_PEPPER: 'CHANGE_ME_RANDOM_32_BYTES_USER_PEPPER', MASTER_KEY_V1_HEX: 'CHANGE_ME_GENERATE_64_HEX_CHARS_WITH_CSPRNG',
    }), ErrorConfiguracion);
    return e;
  });

  test('CHANGE_ME: mensajes nombran las variables', () => {
    try {
      validarConfig({ ...VALIDAS, USER_REF_PEPPER: 'CHANGE_ME_x', MASTER_KEY_V1_HEX: 'CHANGE_ME_y' });
      assert.fail('debía lanzar');
    } catch (e) {
      assert.ok(e instanceof ErrorConfiguracion);
      assert.ok(e.problemas.some((p) => p.startsWith('USER_REF_PEPPER')));
      assert.ok(e.problemas.some((p) => p.startsWith('MASTER_KEY_V1_HEX')));
    }
  });

  test('acumula todos los problemas: faltantes, rangos y enumerados', () => {
    const { USER_REF_PEPPER: _a, ...sinPepper } = VALIDAS;
    try {
      validarConfig({
        ...sinPepper, PORT: '99999', TLS_MODE: 'caddy', HEURISTICS_MODE: 'nube', JWT_TTL_SECONDS: 'cinco',
        DAILY_IP_PEPPER_SEED: 'corta', MASTER_KEY_V1_HEX: 'zz', CORS_ALLOWED_ORIGINS: 'https://ok.local,javascript:alert(1)',
      });
      assert.fail('debía lanzar');
    } catch (e) {
      assert.ok(e instanceof ErrorConfiguracion);
      const t = e.problemas.join('\n');
      for (const esperado of ['Falta USER_REF_PEPPER', 'PORT', 'TLS_MODE', 'HEURISTICS_MODE', 'JWT_TTL_SECONDS', 'DAILY_IP_PEPPER_SEED', 'MASTER_KEY_V1_HEX', 'Origen CORS']) {
        assert.ok(t.includes(esperado), `falta mensaje de ${esperado}:\n${t}`);
      }
    }
  });

  test('TLS_CA_PUBLIC_PATH es opcional y se resuelve respecto a backend/', () => {
    assert.equal(validarConfig({ ...VALIDAS }, { base: '/srv/backend' }).tls.caPublica, null);
    assert.equal(validarConfig({ ...VALIDAS, TLS_CA_PUBLIC_PATH: './certs/ca.crt' }, { base: '/srv/backend' }).tls.caPublica, '/srv/backend/certs/ca.crt');
  });

  test('TLS_MODE=off no se admite en producción', () => {
    assert.throws(() => validarConfig({ ...VALIDAS, NODE_ENV: 'production', TLS_MODE: 'off' }), /TLS_MODE=off/);
    assert.equal(validarConfig({ ...VALIDAS, TLS_MODE: 'off' }).tls.cert, null);
  });

  test('cargarConfig: el entorno del proceso tiene prioridad sobre el archivo', () => {
    const dir = mkdtempSync(join(tmpdir(), 'cfg-'));
    try {
      const ruta = join(dir, '.env');
      writeFileSync(ruta, Object.entries(VALIDAS).map(([k, v]) => `${k}=${v}`).join('\n'));
      const c = cargarConfig({ rutaEnv: ruta, env: { PORT: '9443' }, base: dir });
      assert.equal(c.puerto, 9443);
      assert.equal(c.baseDatos.ruta, join(dir, 'data/prueba.db'));
      assert.throws(() => cargarConfig({ rutaEnv: join(dir, 'no-existe'), env: {} }), ErrorConfiguracion);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('firmas (signing_keys)', () => {
  test('genera la clave activa si no existe, la persiste cifrada y la recupera', () => {
    const db = abrirBaseDatos(':memory:');
    const repos = crearRepositorios(db);
    const vault = crearVault({ llaves: { v1: Buffer.alloc(32, 7) }, versionActiva: 'v1' });
    const f1 = crearFirmas({ repos, vault });
    const { kid, privateKey } = f1.activa();
    assert.equal(repos.signingKeys.activa().kid, kid);
    assert.ok(!repos.signingKeys.activa().private_ct.toString('utf8').includes('PRIVATE KEY'));

    // Una segunda instancia (reinicio) reutiliza la misma clave.
    const f2 = crearFirmas({ repos, vault });
    assert.equal(f2.activa().kid, kid);
    assert.equal(f2.jwks().keys.length, 1);

    const token = signMfaJwt({ privateKey, kid, issuer: 'i', audience: 'a', subject: 's' });
    assert.equal(verifyMfaJwt(token, { buscarClave: (k) => f2.buscarClave(k), issuer: 'i', audience: 'a' }).valid, true);

    const r = f2.rotar();
    assert.equal(r.previous_kid, kid);
    assert.notEqual(r.new_kid, kid);
    assert.equal(f2.activa().kid, r.new_kid);
    assert.equal(f2.jwks().keys.length, 2);
    // f1 todavía no recargó, pero acepta tokens de la clave nueva consultando la base.
    assert.ok(f1.buscarClave(r.new_kid));
    assert.equal(f1.buscarClave('inexistente'), null);
    db.close();
  });

  test('una llave maestra distinta no descifra la clave privada', () => {
    const db = abrirBaseDatos(':memory:');
    const repos = crearRepositorios(db);
    crearFirmas({ repos, vault: crearVault({ llaves: { v1: Buffer.alloc(32, 1) }, versionActiva: 'v1' }) }).activa();
    const otra = crearFirmas({ repos, vault: crearVault({ llaves: { v1: Buffer.alloc(32, 2) }, versionActiva: 'v1' }) });
    assert.throws(() => otra.activa(), /descifrar/);
    db.close();
  });
});

describe('generar-env', () => {
  const PLANTILLA = [
    '# comentario CHANGE_ME que no se toca',
    'MASTER_KEY_VERSION=v1',
    'MASTER_KEY_V1_HEX=CHANGE_ME_GENERATE_64_HEX_CHARS_WITH_CSPRNG',
    'USER_REF_PEPPER=CHANGE_ME_RANDOM_32_BYTES_USER_PEPPER',
    'TOTP_ISSUER=OrganismoRealSoberanoTOTP',
    'PORT=8443',
  ].join('\n');

  test('sustituye cada CHANGE_ME por aleatorio fuerte y fija el emisor neutro', () => {
    const texto = generarContenido(PLANTILLA);
    const v = parsearEnv(texto);
    assert.match(v.MASTER_KEY_V1_HEX, /^[0-9a-f]{64}$/);
    assert.match(v.USER_REF_PEPPER, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(v.TOTP_ISSUER, EMISOR_TOTP_POR_DEFECTO);
    assert.equal(v.PORT, '8443');
    assert.ok(texto.startsWith('# comentario CHANGE_ME que no se toca\n'));
    assert.ok(!/=.*CHANGE_ME/.test(texto));
    assert.notEqual(generarContenido(PLANTILLA), texto, 'cada ejecución genera secretos nuevos');
  });

  test('el .env generado desde el .env.example del repositorio es una configuración válida', async () => {
    const { readFileSync } = await import('node:fs');
    const v = parsearEnv(generarContenido(readFileSync(new URL('../../../../.env.example', import.meta.url), 'utf8')));
    const c = validarConfig(v, { base: '/srv/backend' });
    assert.equal(c.emisorTotp, 'ServicioSoberanoTOTP');
    assert.equal(v.TLS_CA_PUBLIC_PATH, './certs/ca.crt');
    assert.equal(c.tls.caPublica, '/srv/backend/certs/ca.crt');
  });
});
