import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analizarArgumentos, cargarConfig, esHostLocal, exigirDestinoPermitido } from '../lib/config.js';
import { distribucionEstados, enParalelo, formatearDistribucion, percentil, resumenLatencias, tasa } from '../lib/metricas.js';
import { anchoVisible, color, marca, sinAnsi, tabla, usarColor } from '../lib/consola.js';
import { analizarOtpauth, codigoActual, codigoEnPaso, codigoIncorrecto, codigoNuevo, pasoActual } from '../lib/totp.js';
import { escaparHtml, generarHtml, marcaFecha, resumir } from '../lib/informe.js';
import { crearResultado, formatearValor } from '../lib/escenario.js';
import { analizarMetricas, deltaMetrica, filtraDetallesInternos, origenesSimulados, sumarMetrica } from '../lib/servicio.js';
import { base32Encode } from '../../backend/src/core/totp/base32.js';

// ---------------------------------------------------------------- config / guardia de destino

test('solo se aceptan hosts locales salvo --permitir-host', () => {
  for (const h of ['localhost', '127.0.0.1', '127.3.4.5', '::1', '[::1]', 'api.localhost']) assert.equal(esHostLocal(h), true, h);
  for (const h of ['example.com', '10.0.0.1', '192.168.1.10', 'localhost.evil.com', '0.0.0.0']) assert.equal(esHostLocal(h), false, h);
  assert.throws(() => exigirDestinoPermitido('https://example.com:8443', false), /permitir-host/);
  assert.equal(exigirDestinoPermitido('https://example.com:8443', true).hostname, 'example.com');
  assert.throws(() => exigirDestinoPermitido('ftp://localhost', false), /Protocolo/);
});

test('cargarConfig: argumentos, entorno y restricciones', () => {
  const c = cargarConfig(['--url', 'https://127.0.0.1:9000/', '--client-id', 'app1', '--client-secret=s1', '--inseguro', '--sin-color'], {});
  assert.equal(c.url, 'https://127.0.0.1:9000');
  assert.deepEqual(c.apps, [{ clientId: 'app1', clientSecret: 's1' }]);
  assert.equal(c.inseguro, true);
  assert.equal(c.color, false);
  assert.equal(c.ca, null);
  const e = cargarConfig([], { ATTACK_CLIENT_ID: 'a', ATTACK_CLIENT_SECRET: 'b', ATTACK_CLIENT_ID_2: 'c', ATTACK_CLIENT_SECRET_2: 'd' });
  assert.equal(e.apps.length, 2);
  assert.throws(() => cargarConfig(['--url', 'https://victima.example'], {}), /rechazado/);
  assert.throws(() => cargarConfig(['--url', 'https://propio.example', '--permitir-host', '--inseguro'], {}), /inseguro/);
});

test('analizarArgumentos', () => {
  const { opciones, posicionales } = analizarArgumentos(['x', '--a', '1', '--b', '--c=3', '--', '--d']);
  assert.deepEqual(opciones, { a: '1', b: true, c: '3' });
  assert.deepEqual(posicionales, ['x', '--d']);
});

// ---------------------------------------------------------------- métricas

test('percentiles por interpolación lineal', () => {
  const v = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
  assert.equal(percentil(v, 50), 5.5);
  assert.equal(percentil(v, 0), 1);
  assert.equal(percentil(v, 100), 10);
  assert.ok(Math.abs(percentil(v, 95) - 9.55) < 1e-9);
  assert.equal(percentil([], 50), null);
  assert.equal(percentil([7], 95), 7);
  assert.equal(percentil([3, NaN, 1], 50), 2);
});

test('resumen de latencias, tasas y distribución', () => {
  const r = resumenLatencias([10, 20, 30, 40]);
  assert.equal(r.n, 4);
  assert.equal(r.min, 10);
  assert.equal(r.max, 40);
  assert.equal(r.p50, 25);
  assert.equal(r.media, 25);
  assert.equal(resumenLatencias([]).p95, null);
  assert.equal(tasa(1, 3), 33.3);
  assert.equal(tasa(1, 0), 0);
  const d = distribucionEstados([{ status: 429 }, { status: 200 }, { status: 429 }, { status: 0, error: 'ECONNRESET' }]);
  assert.deepEqual(d, { 200: 1, 429: 2, ECONNRESET: 1 });
  assert.equal(formatearDistribucion({ 200: 1, 429: 2 }), '200×1 429×2');
});

test('enParalelo respeta la concurrencia y conserva el orden', async () => {
  let enVuelo = 0;
  let maximo = 0;
  const r = await enParalelo(20, 4, async (i) => {
    enVuelo++;
    maximo = Math.max(maximo, enVuelo);
    await new Promise((s) => setTimeout(s, 5));
    enVuelo--;
    return i * 2;
  });
  assert.equal(maximo, 4);
  assert.deepEqual(r, Array.from({ length: 20 }, (_, i) => i * 2));
});

// ---------------------------------------------------------------- consola

test('tabla alinea texto con y sin colores', () => {
  usarColor(true);
  const t = tabla(['A', 'Bbb'], [[color('verde', 'ok'), 'x'], ['largo', marca(false)]]);
  const lineas = t.split('\n').map(sinAnsi);
  assert.equal(new Set(lineas.map((l) => [...l].length)).size, 1, 'todas las líneas miden lo mismo');
  assert.ok(t.includes('\x1b[32m'));
  usarColor(false);
  assert.equal(color('rojo', 'x'), 'x');
  assert.equal(marca(true), 'OK');
  assert.equal(marca(null), 'INFO');
  assert.equal(anchoVisible('\x1b[31mhola\x1b[0m'), 4);
  assert.ok(tabla(['x'], [['a'.repeat(100)]], { anchoMax: 10 }).includes('…'));
});

// ---------------------------------------------------------------- TOTP

const SEMILLA_RFC = Buffer.from('12345678901234567890123456789012', 'ascii'); // RFC 6238, SHA-256

test('analizarOtpauth y códigos compatibles con el RFC 6238', () => {
  const uri = `otpauth://totp/Mincyt:lab-1?secret=${base32Encode(SEMILLA_RFC)}&issuer=Mincyt&algorithm=SHA256&digits=8&period=30`;
  const d = analizarOtpauth(uri);
  assert.equal(d.algoritmo, 'SHA256');
  assert.equal(d.digitos, 8);
  assert.equal(d.periodo, 30);
  assert.equal(d.emisor, 'Mincyt');
  assert.equal(d.cuenta, 'lab-1');
  assert.ok(d.semilla.equals(SEMILLA_RFC));
  assert.equal(codigoActual(d, 59 * 1000), '46119246'); // vector del Apéndice B (T = 59 s)
  assert.throws(() => analizarOtpauth('otpauth://hotp/x?secret=AA'), /inválida/);
  assert.throws(() => analizarOtpauth('otpauth://totp/x?algorithm=SHA1'), /secret/);
});

test('codigoIncorrecto nunca coincide con la ventana', () => {
  const d = { semilla: SEMILLA_RFC, algoritmo: 'SHA256', digitos: 6, periodo: 30 };
  const ahora = Date.now();
  const t = pasoActual(d, ahora);
  const validos = new Set([-3, -2, -1, 0, 1, 2, 3].map((k) => codigoEnPaso(d, t + k)));
  // Azar trucado: los primeros valores generan exactamente códigos válidos.
  const forzados = [...validos].map((c) => Number(c) / 1e6);
  let i = 0;
  const azar = () => (i < forzados.length ? forzados[i++] : 0.123456);
  const c = codigoIncorrecto(d, { ahora, azar });
  assert.equal(validos.has(c), false);
  assert.match(c, /^\d{6}$/);
  assert.match(codigoIncorrecto(null), /^\d{6}$/);
});

test('codigoNuevo no repite pasos y respeta la ventana', async () => {
  const d = { semilla: SEMILLA_RFC, algoritmo: 'SHA256', digitos: 6, periodo: 30 };
  const t = pasoActual(d);
  const u = { datos: d, ultimoPaso: t - 5 };
  const a = await codigoNuevo(u, { ventana: 1 });
  assert.equal(a.paso, t - 1);
  const b = await codigoNuevo(u, { ventana: 1 });
  assert.equal(b.paso, t);
  const c = await codigoNuevo(u, { ventana: 1 });
  assert.equal(c.paso, t + 1);
  assert.equal(await codigoNuevo(u, { ventana: 1, esperar: false }), null);
});

// ---------------------------------------------------------------- servicio / métricas Prometheus

test('lectura de /metrics y deltas', () => {
  const a = analizarMetricas('# HELP x\ntotp_verifications_total{resultado="ok"} 3\ntotp_verifications_total{resultado="anomaly_blocked"} 1\nbasura\n');
  const b = analizarMetricas('totp_verifications_total{resultado="ok"} 5\ntotp_verifications_total{resultado="anomaly_blocked"} 4\n');
  assert.equal(sumarMetrica(a, 'totp_verifications_total'), 4);
  assert.equal(deltaMetrica(a, b, 'totp_verifications_total', 'anomaly'), 3);
  assert.equal(deltaMetrica(null, b, 'x'), null);
});

test('detección de filtraciones internas y orígenes simulados', () => {
  assert.equal(filtraDetallesInternos('{"error":"INVALID_REQUEST","message":"Solicitud inválida."}'), false);
  assert.equal(filtraDetallesInternos('TypeError: x is undefined\n    at verificar (/srv/backend/src/api/servidor.js:10:3)'), true);
  assert.equal(filtraDetallesInternos('SQLITE_CONSTRAINT: UNIQUE'), true);
  const o = origenesSimulados(300, 20);
  assert.equal(new Set(o).size, 300);
  assert.ok(o.every((ip) => esHostLocal(ip)));
  assert.equal(o[0], '127.0.20.2');
});

// ---------------------------------------------------------------- resultados e informe

test('crearResultado: INFO no cuenta como fallo y un error cierra en FALLO', () => {
  const r = crearResultado('x', 'X', 'demuestra');
  r.verificar('a', '1', '1', true);
  r.verificar('b', 'info', 'info', null);
  assert.equal(r.cerrar().ok, true);
  const r2 = crearResultado('y', 'Y', 'd');
  r2.verificar('a', '1', '1', true);
  const c = r2.cerrar(new Error('boom'));
  assert.equal(c.ok, false);
  assert.equal(c.verificaciones.at(-1).obtenido, 'boom');
  assert.equal(crearResultado('z', 'Z', 'd').cerrar().ok, false, 'sin verificaciones no hay OK');
});

test('formatearValor', () => {
  assert.equal(formatearValor({ 200: 2, 429: 1 }), '200×2 429×1');
  assert.match(formatearValor(resumenLatencias([1, 2, 3])), /^p50 2 ms/);
  assert.equal(formatearValor({ aceptadas: 3, cortadas: 1 }), 'aceptadas=3 · cortadas=1');
  assert.equal(formatearValor(null), '—');
});

test('informe HTML autocontenido y escapado', () => {
  const r = crearResultado('replay', 'Replay <b>', 'demuestra & más');
  r.verificar('<script>alert(1)</script>', '401', '401', true);
  r.metrica('latencia', resumenLatencias([1, 2]));
  r.hallazgo('hallazgo "x"');
  const resultados = [r.cerrar()];
  const html = generarHtml({ generado: new Date().toISOString(), destino: 'https://localhost:8443', entorno: { node: 'v22' }, resultados, resumen: resumir(resultados, 1000) });
  assert.ok(!html.includes('<script>'), 'sin scripts ni inyección');
  assert.ok(html.includes('&lt;script&gt;'));
  assert.ok(!/(src|href)=["']https?:/.test(html), 'sin recursos externos');
  assert.ok(html.includes('Replay &lt;b&gt;'));
  assert.match(marcaFecha(new Date('2026-11-26T15:04:05Z')), /^2026-11-26T15-04-05$/);
  assert.equal(escaparHtml(`"'&`), '&quot;&#39;&amp;');
});

test('informe: las rutas absolutas del sistema se sustituyen por relativas o marcadores', async () => {
  const { relativizarRutas } = await import('../lib/informe.js');
  const informe = {
    destino: 'https://localhost:8443',
    resultados: [{ metricas: { comando: 'node src/main.js (cwd /srv/ana/proyectos/repo/backend)' }, notas: ['log en /srv/ana/.tmp-lab/backend.log', 'ca /tmp/x/ca.crt', 'otra /srv/ana/datos'] }],
  };
  const r = relativizarRutas(informe, { repo: '/srv/ana/proyectos/repo', casa: '/srv/ana', temporales: ['/srv/ana/.tmp-lab', '/tmp'] });
  assert.equal(r.resultados[0].metricas.comando, 'node src/main.js (cwd backend)');
  assert.deepEqual(r.resultados[0].notas, ['log en <tmp>/backend.log', 'ca <tmp>/x/ca.crt', 'otra ~/datos']);
  assert.doesNotMatch(JSON.stringify(r), /\/home\/ana/);
});
