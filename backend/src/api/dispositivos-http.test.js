// Prueba de punta a punta por HTTP de la vinculación de dispositivos (issue #47) con el arranque
// real (main.js): CA publicada con TLS_CA_PUBLIC_PATH → huella en `provisioning`, último uso,
// consulta y desvinculación (que revoca y hace fallar verify igual que un código incorrecto).

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { iniciar } from '../main.js';
import { validarConfig } from '../infrastructure/config/config.js';
import { hashSecreto } from '../security/index.js';
import { generateTotp } from '../core/totp/totp.js';
import { base32Decode } from '../core/totp/base32.js';

function pedir(puerto, { metodo = 'GET', ruta, cuerpo, cabeceras = {} }) {
  return new Promise((resolver, rechazar) => {
    const datos = cuerpo === undefined ? undefined : JSON.stringify(cuerpo);
    const h = { ...cabeceras, ...(datos ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(datos) } : {}) };
    const req = request({ host: '127.0.0.1', port: puerto, method: metodo, path: ruta, headers: h }, (res) => {
      const trozos = [];
      res.on('data', (t) => trozos.push(t));
      res.on('end', () => {
        const texto = Buffer.concat(trozos).toString('utf8');
        let json = null;
        try { json = JSON.parse(texto); } catch { /* no JSON */ }
        resolver({ status: res.statusCode, cabeceras: res.headers, json });
      });
    });
    req.on('error', rechazar);
    if (datos) req.write(datos);
    req.end();
  });
}

/** Certificado autofirmado de prueba con openssl (si no está disponible, la prueba se omite). */
function certificadoDePrueba(carpeta) {
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1',
      '-subj', '/CN=CA de prueba', '-keyout', join(carpeta, 'ca.key'), '-out', join(carpeta, 'ca.crt')], { stdio: 'ignore' });
    return join(carpeta, 'ca.crt');
  } catch {
    return null;
  }
}

describe('HTTP: vinculación de dispositivos (main.js real)', () => {
  test('enrolar con device → activar → verificar → consultar → desvincular', async (t) => {
    const carpeta = mkdtempSync(join(tmpdir(), 'totp-disp-'));
    const ca = certificadoDePrueba(carpeta);
    if (!ca) { rmSync(carpeta, { recursive: true, force: true }); t.skip('openssl no disponible'); return; }
    const config = validarConfig({
      HOST: '127.0.0.1', PORT: '0', TLS_MODE: 'off', SQLITE_DB_PATH: ':memory:', HEURISTICS_MODE: 'mock',
      MASTER_KEY_VERSION: 'v1', MASTER_KEY_V1_HEX: 'ab'.repeat(32), TLS_CA_PUBLIC_PATH: ca,
      USER_REF_PEPPER: 'p'.repeat(43), DAILY_IP_PEPPER_SEED: 'q'.repeat(43),
    });
    const silencio = { info() {}, warn() {}, error() {} };
    const svc = await iniciar({ config, registro: silencio, senales: false });
    try {
      svc.repos.apps.crear({ nombre: 'Portal', client_id: 'portal-disp', secret_hash: hashSecreto('secreto-disp') });
      const cred = { 'x-client-id': 'portal-disp', 'x-client-secret': 'secreto-disp' };
      const huella = new X509Certificate(readFileSync(ca)).fingerprint256;

      const e = await pedir(svc.puerto, { metodo: 'POST', ruta: '/api/v1/enrollments', cabeceras: cred,
        cuerpo: { user_ref: 'ciudadano-http', device: { name: 'Teléfono de prueba', platform: 'android' } } });
      assert.equal(e.status, 201, JSON.stringify(e.json));
      assert.equal(e.cabeceras['cache-control'], 'no-store');
      assert.equal(e.json.provisioning.ca_fingerprint_sha256, huella);
      assert.equal(e.json.provisioning.device_id, e.json.device_id);
      const id = e.json.enrollment_id;
      const semilla = base32Decode(new URL(e.json.otpauth_uri).searchParams.get('secret'));
      const pol = { algoritmo: e.json.algoritmo, digitos: e.json.digitos, periodo: e.json.periodo };
      const ahora = Date.now();

      const a = await pedir(svc.puerto, { metodo: 'POST', ruta: `/api/v1/enrollments/${id}/activate`, cabeceras: cred,
        cuerpo: { code: generateTotp(semilla, ahora, pol) } });
      assert.equal(a.status, 200, JSON.stringify(a.json));
      const d0 = await pedir(svc.puerto, { ruta: `/api/v1/enrollments/${id}/device`, cabeceras: cred });
      assert.equal(d0.status, 200);
      assert.equal(d0.json.name, 'Teléfono de prueba');

      // Código del paso siguiente (el de la activación ya está consumido; la ventana ±1 lo acepta).
      const v = await pedir(svc.puerto, { metodo: 'POST', ruta: '/api/v1/verify', cabeceras: cred,
        cuerpo: { user_ref: 'ciudadano-http', code: generateTotp(semilla, ahora + pol.periodo * 1000, pol) } });
      assert.equal(v.status, 200, JSON.stringify(v.json));
      const d1 = await pedir(svc.puerto, { ruta: `/api/v1/enrollments/${id}/device`, cabeceras: cred });
      assert.ok(d1.json.last_used_at >= d0.json.last_used_at);
      assert.equal(d1.json.enrollment_estado, 'activo');

      const x = await pedir(svc.puerto, { metodo: 'DELETE', ruta: `/api/v1/enrollments/${id}/device`, cabeceras: cred });
      assert.equal(x.status, 200);
      assert.equal(x.json.estado, 'revocado');
      const tras = await pedir(svc.puerto, { metodo: 'POST', ruta: '/api/v1/verify', cabeceras: cred,
        cuerpo: { user_ref: 'ciudadano-http', code: generateTotp(semilla, ahora + 2 * pol.periodo * 1000, pol) } });
      const mal = await pedir(svc.puerto, { metodo: 'POST', ruta: '/api/v1/verify', cabeceras: cred,
        cuerpo: { user_ref: 'nadie', code: '123456' } });
      assert.equal(tras.status, 401);
      assert.deepEqual(tras.json, mal.json);
      assert.equal((await pedir(svc.puerto, { ruta: `/api/v1/enrollments/${id}/device` })).status, 401, 'sin credenciales');
    } finally {
      await svc.detener('prueba');
      rmSync(carpeta, { recursive: true, force: true });
    }
  });
});
