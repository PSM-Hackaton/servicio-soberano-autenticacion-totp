// Pruebas del proxy de caos contra un servidor eco TCP local y del cliente HTTP a través del proxy.

import { test, after, before } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';

import { analizarDestino, crearProxyCaos } from '../caos/proxy-caos.js';
import { crearCliente } from '../lib/http.js';

/** Servidor eco: devuelve lo que recibe. */
let eco;
let puertoEco;
/** Servidor HTTP mínimo para el cliente. */
let web;
let puertoWeb;

before(async () => {
  eco = net.createServer((s) => { s.on('error', () => {}); s.pipe(s); });
  await new Promise((r) => eco.listen(0, '127.0.0.1', r));
  puertoEco = eco.address().port;
  web = http.createServer((req, res) => {
    let cuerpo = '';
    req.on('data', (t) => { cuerpo += t; });
    req.on('end', () => {
      if (req.url === '/lento') { setTimeout(() => res.end('{}'), 500); return; }
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ metodo: req.method, url: req.url, cuerpo, ip: req.socket.remoteAddress, cabeceras: req.headers }));
    });
  });
  await new Promise((r) => web.listen(0, '0.0.0.0', r));
  puertoWeb = web.address().port;
});

after(async () => {
  await new Promise((r) => eco.close(r));
  web.closeAllConnections?.();
  await new Promise((r) => web.close(r));
});

/** Abre una conexión, envía `texto` y devuelve { datos, ms } o { error }. */
function enviar(puerto, texto, { timeoutMs = 2000 } = {}) {
  return new Promise((resolver) => {
    const t0 = performance.now();
    const s = net.connect({ host: '127.0.0.1', port: puerto });
    let datos = '';
    const fin = (r) => { clearTimeout(tm); s.destroy(); resolver({ ...r, ms: performance.now() - t0 }); };
    const tm = setTimeout(() => fin({ error: 'TIEMPO_AGOTADO', datos }), timeoutMs);
    s.on('connect', () => s.write(texto));
    s.on('data', (d) => { datos += d; if (datos.length >= texto.length) fin({ datos }); });
    s.on('error', (e) => fin({ error: e.code ?? e.message, datos }));
    s.on('close', () => fin({ error: datos.length ? null : 'CERRADA', datos }));
  });
}

async function nuevoProxy(extra = {}) {
  const p = crearProxyCaos({ destino: { host: '127.0.0.1', port: puertoEco }, ...extra });
  const dir = await p.iniciar();
  return { p, puerto: dir.port };
}

test('reenvía en ambos sentidos sin alterar los datos', async () => {
  const { p, puerto } = await nuevoProxy();
  const texto = 'hola caos '.repeat(1000);
  const r = await enviar(puerto, texto);
  assert.equal(r.error, undefined);
  assert.equal(r.datos, texto);
  assert.equal(p.estadisticas.reenviadas, 1);
  assert.ok(p.estadisticas.bytesSubida >= texto.length);
  await p.detener();
});

test('añade latencia (RTT) y la quita al restaurar', async () => {
  const { p, puerto } = await nuevoProxy();
  const base = await enviar(puerto, 'x');
  p.configurar({ latenciaMs: 300 });
  const lento = await enviar(puerto, 'x');
  assert.equal(lento.datos, 'x');
  // conexión retrasada (150) + ida (150) + vuelta (150)
  assert.ok(lento.ms >= 400, `latencia medida ${lento.ms} ms`);
  p.restaurar();
  const rapido = await enviar(puerto, 'x');
  assert.ok(rapido.ms < base.ms + 100, `tras restaurar ${rapido.ms} ms`);
  await p.detener();
});

test('mantiene el orden de los trozos con latencia y jitter', async () => {
  const { p, puerto } = await nuevoProxy();
  p.configurar({ latenciaMs: 100, jitterMs: 90 });
  const texto = Array.from({ length: 200 }, (_, i) => `[${i}]`).join('');
  const r = await new Promise((resolver) => {
    const s = net.connect({ host: '127.0.0.1', port: puerto });
    let datos = '';
    s.on('connect', async () => {
      for (let i = 0; i < texto.length; i += 37) { s.write(texto.slice(i, i + 37)); await new Promise((z) => setTimeout(z, 2)); }
    });
    s.on('data', (d) => { datos += d; if (datos.length >= texto.length) { s.destroy(); resolver(datos); } });
  });
  assert.equal(r, texto);
  await p.detener();
});

test('corte total: cierra activas y rechaza nuevas; restaurar recupera', async () => {
  const { p, puerto } = await nuevoProxy();
  // Conexión activa que quedará abierta.
  const activa = net.connect({ host: '127.0.0.1', port: puerto });
  const cerrada = new Promise((r) => activa.on('close', r));
  activa.on('error', () => {});
  await new Promise((r) => activa.on('connect', r));
  await new Promise((r) => setTimeout(r, 50));
  p.configurar({ corte: true });
  await cerrada;
  const r = await enviar(puerto, 'x');
  assert.notEqual(r.datos, 'x');
  assert.ok(p.estadisticas.rechazadasCorte >= 1);
  assert.ok(p.estadisticas.cortadas >= 1);
  p.restaurar();
  const ok = await enviar(puerto, 'x');
  assert.equal(ok.datos, 'x');
  await p.detener();
});

test('pérdida 100 % en modo reset y en modo silencio', async () => {
  const { p, puerto } = await nuevoProxy();
  p.configurar({ perdidaPct: 100, modoPerdida: 'reset' });
  const r1 = await enviar(puerto, 'x');
  assert.ok(r1.error, 'reset: la conexión falla');
  p.configurar({ modoPerdida: 'silencio' });
  const r2 = await enviar(puerto, 'x', { timeoutMs: 300 });
  assert.equal(r2.error, 'TIEMPO_AGOTADO', 'silencio: el cliente agota su espera');
  assert.equal(p.estadisticas.perdidas, 2);
  p.configurar({ perdidaPct: 0 });
  assert.equal((await enviar(puerto, 'x')).datos, 'x');
  await p.detener();
});

test('pérdida parcial con azar determinista', async () => {
  const secuencia = [0.1, 0.9, 0.1, 0.9]; // < 0.5 → se pierde
  let i = 0;
  const { p, puerto } = await nuevoProxy({ azar: () => secuencia[i++ % secuencia.length] });
  p.configurar({ perdidaPct: 50 });
  const r = [];
  for (let k = 0; k < 4; k++) r.push(await enviar(puerto, 'x'));
  assert.deepEqual(r.map((x) => x.datos === 'x'), [false, true, false, true]);
  await p.detener();
});

test('cortarConexiones mata solo las activas', async () => {
  const { p, puerto } = await nuevoProxy();
  const s = net.connect({ host: '127.0.0.1', port: puerto });
  s.on('error', () => {});
  const cerrada = new Promise((r) => s.on('close', r));
  await new Promise((r) => s.on('connect', r));
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(p.cortarConexiones(), 1);
  await cerrada;
  assert.equal((await enviar(puerto, 'x')).datos, 'x');
  await p.detener();
});

test('el proxy se niega a apuntar fuera de localhost', () => {
  assert.throws(() => crearProxyCaos({ destino: { host: 'example.com', port: 443 } }), /permitir-host/);
  assert.doesNotThrow(() => crearProxyCaos({ destino: { host: 'example.com', port: 443 }, permitirHost: true }));
  assert.deepEqual(analizarDestino('localhost:8443'), { host: 'localhost', port: 8443 });
  assert.deepEqual(analizarDestino('[::1]:9'), { host: '::1', port: 9 });
  assert.throws(() => analizarDestino('sin-puerto'), /inválido/);
});

// ---------------------------------------------------------------- cliente HTTP

test('cliente HTTP: JSON, credenciales, origen simulado y errores de red sin excepciones', async () => {
  const c = crearCliente({ url: `http://127.0.0.1:${puertoWeb}`, clientId: 'app', clientSecret: 's', timeoutMs: 300 });
  const r = await c.post('/eco', { a: 1 });
  assert.equal(r.status, 200);
  assert.equal(r.cuerpo.cuerpo, '{"a":1}');
  assert.equal(r.cuerpo.cabeceras['x-client-id'], 'app');
  assert.equal(r.cuerpo.cabeceras['content-type'], 'application/json');
  const sin = await c.get('/x', { sinCredenciales: true });
  assert.equal(sin.cuerpo.cabeceras['x-client-id'], undefined);
  const chunked = await c.peticion('POST', '/x', { crudo: 'abc', sinLongitud: true });
  assert.equal(chunked.cuerpo.cabeceras['transfer-encoding'], 'chunked');
  if (process.platform === 'linux') {
    const o = await c.get('/x', { origen: '127.0.0.77' });
    assert.equal(o.cuerpo.ip.replace('::ffff:', ''), '127.0.0.77');
  }
  const lento = await c.get('/lento');
  assert.equal(lento.status, 0);
  assert.equal(lento.error, 'TIEMPO_AGOTADO');
  const cerrado = crearCliente({ url: 'http://127.0.0.1:1', timeoutMs: 500 });
  const e = await cerrado.get('/');
  assert.equal(e.status, 0);
  assert.equal(e.error, 'ECONNREFUSED');
  assert.throws(() => crearCliente({ url: 'https://example.com', inseguro: true }), /localhost/);
  c.cerrar();
  cerrado.cerrar();
});

test('cliente HTTP a través del proxy con corte: falla con error de red, nunca con 200', async () => {
  const p = crearProxyCaos({ destino: { host: '127.0.0.1', port: puertoWeb } });
  const { port } = await p.iniciar();
  const c = crearCliente({ url: `http://127.0.0.1:${port}`, timeoutMs: 500, keepAlive: true });
  assert.equal((await c.get('/a')).status, 200);
  p.configurar({ corte: true });
  const r = await c.get('/b');
  assert.equal(r.status, 0);
  p.restaurar();
  assert.equal((await c.get('/c')).status, 200);
  c.cerrar();
  await p.detener();
});
