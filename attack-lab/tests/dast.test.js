import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import dast, {
  auditarCabecerasRespuesta,
  auditarCookies,
  auditarCorsRespuesta,
  probarHandshakeTls,
} from '../escenarios/dast.js';
import { correrEscenario, crearContexto } from '../lib/escenario.js';
import { cabecerasSeguridad } from '../../backend/src/security/cabeceras.js';

test('DAST utilidades puras: cabeceras OWASP, cookies y CORS', () => {
  const okCab = auditarCabecerasRespuesta(
    Object.fromEntries(Object.entries(cabecerasSeguridad()).map(([k, v]) => [k.toLowerCase(), v])),
    { ruta: '/api/v1/verify', tipo: 'api', esHttps: true },
  );
  assert.deepEqual(okCab.faltantes, []);
  assert.deepEqual(okCab.inseguras, []);

  // Aviso específico cuando /app/ envía camera=()
  const pwaCab = auditarCabecerasRespuesta(
    Object.fromEntries(Object.entries(cabecerasSeguridad()).map(([k, v]) => [k.toLowerCase(), v])),
    { ruta: '/app/', tipo: 'estatico', esHttps: true },
  );
  assert.equal(pwaCab.avisos.length, 1);

  const malaCab = auditarCabecerasRespuesta({ 'x-powered-by': 'Express' }, { ruta: '/api/v1/verify', tipo: 'api', esHttps: true });
  assert.ok(malaCab.faltantes.length >= 5);
  assert.ok(malaCab.inseguras.some((s) => s.includes('X-Powered-By')));

  const ckOk = auditarCookies('__Host-sid=abc; HttpOnly; Secure; SameSite=Strict; Path=/', { esHttps: true });
  assert.deepEqual(ckOk.problemas, []);

  const ckMala = auditarCookies('sid=abc; Path=/', { esHttps: true });
  assert.equal(ckMala.problemas.length, 3);

  assert.equal(auditarCorsRespuesta({}, 'https://atacante.invalid').ok, true);
  assert.equal(auditarCorsRespuesta({ 'access-control-allow-origin': '*' }, 'https://atacante.invalid').ok, false);
  assert.equal(auditarCorsRespuesta({ 'access-control-allow-origin': 'https://atacante.invalid' }, 'https://atacante.invalid').ok, false);
});

test('DAST en vivo contra servidor HTTPS TLS 1.3: valida TLS 1.3, rechaza TLS 1.2, cabeceras, métodos y CORS', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dast-test-'));
  const keyPath = join(dir, 'key.pem');
  const certPath = join(dir, 'cert.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
    '-keyout', keyPath, '-out', certPath, '-days', '1', '-nodes',
    '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
  ], { stdio: 'ignore' });

  const server = https.createServer({
    key: readFileSync(keyPath),
    cert: readFileSync(certPath),
    minVersion: 'TLSv1.3',
    maxVersion: 'TLSv1.3',
  }, (req, res) => {
    const headers = { ...cabecerasSeguridad(), 'Content-Type': 'application/json; charset=utf-8' };
    if (req.url === '/app/') headers['Permissions-Policy'] = 'camera=(self), microphone=(), geolocation=()';
    if (req.url === '/metrics') {
      const ip = req.socket.remoteAddress?.replace(/^::ffff:/, '');
      if (ip !== '127.0.0.1' && ip !== '::1') {
        res.writeHead(403, headers);
        res.end(JSON.stringify({ error: 'FORBIDDEN', message: 'Solo loopback.' }));
        return;
      }
      res.writeHead(200, { ...headers, 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('# HELP ok\ntotp_health_up 1\n');
      return;
    }
    if (['TRACE', 'PUT', 'PATCH'].includes(req.method) || (req.method === 'DELETE' && !req.url.startsWith('/api/v1/enrollments/')) || (req.method === 'GET' && req.url === '/api/v1/verify')) {
      res.writeHead(405, headers);
      res.end(JSON.stringify({ error: 'METHOD_NOT_ALLOWED', message: 'Método no permitido.' }));
      return;
    }
    if (req.method === 'OPTIONS') {
      res.writeHead(204, headers);
      res.end();
      return;
    }
    if (req.url.startsWith('/admin/api/') && req.url !== '/admin/api/login') {
      res.writeHead(401, headers);
      res.end(JSON.stringify({ error: 'UNAUTHORIZED', message: 'Sesión requerida.' }));
      return;
    }
    if (req.url === '/ruta-inexistente-dast') {
      res.writeHead(404, headers);
      res.end(JSON.stringify({ error: 'NOT_FOUND', message: 'No encontrado.' }));
      return;
    }
    if (req.url.startsWith('/api/v1/')) {
      res.writeHead(401, headers);
      res.end(JSON.stringify({ error: 'UNAUTHORIZED', message: 'Credenciales inválidas.' }));
      return;
    }
    res.writeHead(200, headers);
    res.end(JSON.stringify({ status: 'ok' }));
  });

  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address();
  const url = `https://127.0.0.1:${port}`;

  try {
    const tls13 = await probarHandshakeTls(new URL(url), { ca: certPath, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' });
    assert.equal(tls13.conectado, true);
    assert.equal(tls13.protocolo, 'TLSv1.3');

    const tls12 = await probarHandshakeTls(new URL(url), { inseguro: true, minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2' });
    assert.equal(tls12.conectado, false);

    const ctx = crearContexto({
      url,
      ca: certPath,
      inseguro: false,
      apps: [],
      timeoutMs: 4000,
      ventana: 1,
      detallado: false,
      color: false,
      opciones: {},
    });
    const res = await correrEscenario(dast, ctx, 11);
    ctx.cerrar();
    assert.equal(res.ok, true, JSON.stringify(res.verificaciones.filter((v) => v.ok === false), null, 2));
    assert.equal(res.hallazgos.length, 0);
  } finally {
    await new Promise((r) => server.close(r));
    rmSync(dir, { recursive: true, force: true });
  }
});
