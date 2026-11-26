/** PRNG con semilla (mulberry32) para que la prueba del reservorio sea reproducible. */
function azarDeterminista(semilla) {
  let a = semilla >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  HASH_GENESIS, serializarCanonico, calcularHash, crearBitacora, verificarCadena, respuestaVerificacion,
  crearMetricas, RESULTADOS_VERIFICACION,
} from './index.js';

/** Almacén en memoria que imita la tabla audit_log (id autoincremental). */
function almacenEnMemoria() {
  /** @type {any[]} */
  const filas = [];
  let contador = 0;
  return {
    filas,
    ultimo: () => filas.at(-1),
    insertar: (fila) => { contador++; filas.push({ id: contador, ...fila }); return contador; },
  };
}

/** Reloj de pruebas determinista que avanza 1 s por lectura. */
function relojFijo(inicio = Date.parse('2026-11-26T12:00:00.000Z')) {
  let t = inicio;
  return () => new Date((t += 1000)).toISOString();
}

function cadenaDe(n) {
  const almacen = almacenEnMemoria();
  const bitacora = crearBitacora({ ...almacen, ahora: relojFijo() });
  for (let i = 1; i <= n; i++) {
    bitacora.registrar({ actor: 'admin', accion: 'VERIFY', objetivo: `app-${i % 3}`, detalle: { intento: i, resultado: 'ok' } });
  }
  return almacen.filas;
}

test('génesis: la primera fila enlaza con 64 ceros y su hash es reproducible', () => {
  assert.equal(HASH_GENESIS, '0'.repeat(64));
  const [primera] = cadenaDe(1);
  assert.equal(primera.prev_hash, HASH_GENESIS);
  const contenido = serializarCanonico({
    ts: primera.ts, actor: 'admin', accion: 'VERIFY', objetivo: 'app-1', detalle: primera.detalle,
  });
  const esperado = createHash('sha256').update(`${HASH_GENESIS}|${contenido}`).digest('hex');
  assert.equal(primera.hash, esperado);
  assert.equal(calcularHash(HASH_GENESIS, primera), esperado);
});

test('cadena íntegra con N eventos', () => {
  const filas = cadenaDe(50);
  const r = verificarCadena(filas);
  assert.deepEqual(r, { intact: true, total: 50, brokenAtId: null, lastHash: filas.at(-1).hash });
  for (let i = 1; i < filas.length; i++) assert.equal(filas[i].prev_hash, filas[i - 1].hash);
  assert.deepEqual(respuestaVerificacion(r), {
    intact: true, checked_records: 50, broken_at_id: null, last_hash: filas.at(-1).hash,
  });
});

test('cadena vacía es íntegra', () => {
  assert.deepEqual(verificarCadena([]), { intact: true, total: 0, brokenAtId: null, lastHash: null });
});

test('modificar el detalle de una fila → brokenAtId de esa fila', () => {
  const filas = cadenaDe(10);
  filas[6] = { ...filas[6], detalle: '{"intento":7,"resultado":"fallo"}' };
  const r = verificarCadena(filas);
  assert.equal(r.intact, false);
  assert.equal(r.brokenAtId, 7);
  assert.equal(respuestaVerificacion(r).broken_at_id, 7);
});

test('modificar y recalcular el hash de una fila rompe el enlace de la siguiente', () => {
  const filas = cadenaDe(10);
  const alterada = { ...filas[3], actor: 'intruso' };
  alterada.hash = calcularHash(alterada.prev_hash, alterada);
  filas[3] = alterada;
  assert.equal(verificarCadena(filas).brokenAtId, 5);
});

test('borrar una fila intermedia → salto de prev_hash detectado', () => {
  const filas = cadenaDe(10);
  filas.splice(4, 1); // elimina id 5
  const r = verificarCadena(filas);
  assert.equal(r.intact, false);
  assert.equal(r.brokenAtId, 6);
});

test('reordenar filas → detectado', () => {
  const filas = cadenaDe(6);
  [filas[2], filas[3]] = [filas[3], filas[2]];
  const r = verificarCadena(filas);
  assert.equal(r.intact, false);
  assert.equal(r.brokenAtId, 4);
});

test('serialización canónica independiente del orden de claves', () => {
  const a = { b: 1, a: { y: [3, { q: 1, p: 2 }], x: null }, c: 'texto' };
  const b = { c: 'texto', a: { x: null, y: [3, { p: 2, q: 1 }] }, b: 1 };
  assert.equal(serializarCanonico(a), serializarCanonico(b));
  assert.equal(serializarCanonico(a), '{"a":{"x":null,"y":[3,{"p":2,"q":1}]},"b":1,"c":"texto"}');
  assert.equal(serializarCanonico({ z: undefined, a: 1 }), '{"a":1}');
  const campos = { ts: 't', actor: 'x', accion: 'y', objetivo: null, detalle: a };
  assert.equal(calcularHash(HASH_GENESIS, campos), calcularHash(HASH_GENESIS, { ...campos, detalle: b }));
});

test('detalle filtra claves sensibles, también anidadas y en arreglos', () => {
  const almacen = almacenEnMemoria();
  const bitacora = crearBitacora({ ...almacen, ahora: relojFijo() });
  const fila = bitacora.registrar({
    actor: 'sistema',
    accion: 'ENROLL',
    objetivo: 'usr-1',
    detalle: {
      algoritmo: 'SHA256',
      secret: 'JBSWY3DP',
      otpCode: '123456',
      cliente: { clientSecret: 'abc', nombre: 'app', anidado: { semilla: 'xyz', PIN: '0000' } },
      lista: [{ token: 'eyJ...' }, { password: 'p', shipping: 'si' }],
    },
  });
  const detalle = JSON.parse(fila.detalle);
  assert.equal(detalle.algoritmo, 'SHA256');
  assert.equal(detalle.secret, '[oculto]');
  assert.equal(detalle.otpCode, '[oculto]');
  assert.equal(detalle.cliente.clientSecret, '[oculto]');
  assert.equal(detalle.cliente.nombre, 'app');
  assert.equal(detalle.cliente.anidado.semilla, '[oculto]');
  assert.equal(detalle.cliente.anidado.PIN, '[oculto]');
  assert.equal(detalle.lista[0].token, '[oculto]');
  assert.equal(detalle.lista[1].password, '[oculto]');
  assert.equal(detalle.lista[1].shipping, 'si');
  for (const secreto of ['JBSWY3DP', '123456', 'abc', 'xyz', '0000', 'eyJ...']) {
    assert.ok(!fila.detalle.includes(secreto), `no debe filtrarse ${secreto}`);
  }
  // Lo guardado en el almacén es lo mismo que se devuelve y verifica.
  assert.equal(almacen.filas[0].detalle, fila.detalle);
  assert.equal(verificarCadena(almacen.filas).intact, true);
});

test('detalle como texto JSON también se filtra; sin detalle queda null', () => {
  const almacen = almacenEnMemoria();
  const bitacora = crearBitacora({ ...almacen, ahora: relojFijo() });
  const f1 = bitacora.registrar({ actor: 'a', accion: 'b', detalle: '{"code":"999999","ok":true}' });
  assert.equal(f1.detalle, '{"code":"[oculto]","ok":true}');
  const f2 = bitacora.registrar({ actor: 'a', accion: 'b' });
  assert.equal(f2.detalle, null);
  assert.equal(f2.objetivo, null);
  assert.equal(f2.id, 2);
  assert.equal(verificarCadena(almacen.filas).intact, true);
});

test('registrar exige actor y accion', () => {
  const bitacora = crearBitacora(almacenEnMemoria());
  assert.throws(() => bitacora.registrar({ actor: '', accion: 'x' }));
  assert.throws(() => crearBitacora({}));
});

// ---------------------------------------------------------------- métricas

/** Reloj controlable en milisegundos. */
function relojMs(inicio = 1_800_000_000_000) {
  const r = { t: inicio, ahora: () => r.t };
  return r;
}

test('métricas: percentiles razonables por ruta', () => {
  const reloj = relojMs();
  const m = crearMetricas({ ahora: reloj.ahora });
  for (let i = 1; i <= 100; i++) m.registrarPeticion({ ruta: '/v1/totp/verify', status: 200, duracionMs: i });
  m.registrarPeticion({ ruta: '/healthz?x=1', status: 200, duracionMs: 2 });
  const s = m.instantanea();
  const verify = s.latenciaPorRuta['/v1/totp/verify'];
  assert.equal(verify.total, 100);
  assert.equal(verify.p50Ms, 50);
  assert.equal(verify.p95Ms, 95);
  assert.ok(s.latenciaPorRuta['/healthz'], 'la ruta se normaliza sin query');
});

test('métricas: disponibilidad, tasa de 5xx y ventana deslizante', () => {
  const reloj = relojMs();
  const m = crearMetricas({ ahora: reloj.ahora, ventanaMs: 60_000 });
  for (let i = 0; i < 9; i++) m.registrarPeticion({ ruta: '/a', status: 200, duracionMs: 1 });
  m.registrarPeticion({ ruta: '/a', status: 503, duracionMs: 1 });
  let s = m.instantanea();
  assert.equal(s.disponibilidadPct, 90);
  assert.equal(s.tasa5xx, 0.1);
  assert.equal(s.ventana.peticiones, 10);
  assert.equal(s.ventana.tasa5xx, 0.1);

  reloj.t += 5 * 60_000; // la ventana expira
  s = m.instantanea();
  assert.equal(s.ventana.peticiones, 0);
  assert.equal(s.totales.peticiones, 10);
  assert.equal(s.uptimeSegundos, 300);

  m.registrarChequeoSalud(true);
  m.registrarChequeoSalud(true);
  m.registrarChequeoSalud(true);
  m.registrarChequeoSalud(false);
  assert.equal(m.instantanea().disponibilidadPct, 75, 'con chequeos, la disponibilidad usa la salud');
});

test('métricas: resultados de verificación, inferencia, base de datos y reloj', () => {
  const m = crearMetricas({ ahora: relojMs().ahora });
  for (const r of RESULTADOS_VERIFICACION) m.registrarResultadoVerificacion(r);
  m.registrarResultadoVerificacion('ok');
  assert.throws(() => m.registrarResultadoVerificacion('otro'));
  m.registrarInferencia(1);
  m.registrarInferencia(3);
  m.registrarErrorBaseDatos();
  m.registrarReconexion();
  m.fijarDesfaseReloj(-120);
  const s = m.instantanea();
  assert.equal(s.resultadosVerificacion.ok, 2);
  assert.equal(s.resultadosVerificacion.anomaly_blocked, 1);
  assert.equal(s.totales.verificaciones, 7);
  assert.equal(s.inferencia.mediaMs, 2);
  assert.equal(s.totales.erroresBaseDatos, 1);
  assert.equal(s.totales.reconexiones, 1);
  assert.equal(s.desfaseRelojMs, -120);
  assert.match(s.inicio, /^\d{4}-\d{2}-\d{2}T/);
});

test('métricas: formatoTexto expone nombres esperados', () => {
  const m = crearMetricas({ ahora: relojMs().ahora });
  m.registrarPeticion({ ruta: '/v1/totp/verify', status: 200, duracionMs: 4 });
  m.registrarResultadoVerificacion('replay');
  m.registrarChequeoSalud(true);
  const texto = m.formatoTexto();
  for (const nombre of [
    'totp_uptime_seconds', 'totp_http_requests_total{ruta="/v1/totp/verify"} 1',
    'totp_http_request_duration_ms{ruta="/v1/totp/verify",quantile="0.95"} 4',
    'totp_http_5xx_ratio', 'totp_availability_percent 100', 'totp_health_up 1',
    'totp_verifications_total{resultado="replay"} 1', 'totp_db_errors_total 0',
    'totp_db_reconnections_total', 'totp_anomaly_inference_ms_avg', 'totp_clock_skew_ms',
  ]) assert.ok(texto.includes(nombre), `falta ${nombre}`);
  assert.ok(texto.endsWith('\n'));
  assert.match(texto, /# TYPE totp_verifications_total counter/);
});

test('métricas: el reservorio y las rutas no crecen sin límite', () => {
  const reloj = relojMs();
  const m = crearMetricas({ ahora: reloj.ahora, capacidadReservorio: 128, maxRutas: 4, azar: azarDeterminista(42) });
  for (let i = 0; i < 20_000; i++) {
    reloj.t += 50;
    m.registrarPeticion({ ruta: '/v1/totp/verify', status: 200, duracionMs: i % 100 });
    m.registrarInferencia(i % 10);
  }
  for (let i = 0; i < 50; i++) m.registrarPeticion({ ruta: `/ruta/${i}`, status: 404, duracionMs: 1 });
  const s = m.instantanea();
  const verify = s.latenciaPorRuta['/v1/totp/verify'];
  assert.equal(verify.total, 20_000);
  assert.equal(verify.muestras, 128);
  assert.ok(verify.p50Ms >= 30 && verify.p50Ms <= 70, `p50 muestreado razonable: ${verify.p50Ms}`);
  assert.ok(Object.keys(s.latenciaPorRuta).length <= 5, 'rutas acotadas (más "otras")');
  assert.ok(s.latenciaPorRuta.otras.total > 0);
});

test('métricas: no exponen IP ni identificadores de usuario', () => {
  const m = crearMetricas({ ahora: relojMs().ahora });
  // Aunque el llamador pase campos extra, solo se usan ruta, status y duracionMs.
  m.registrarPeticion(/** @type {any} */ ({ ruta: '/v1/totp/verify', status: 200, duracionMs: 1, ip: '10.0.0.7', usuario: 'usr-42' }));
  const salida = JSON.stringify(m.instantanea()) + m.formatoTexto();
  assert.ok(!salida.includes('10.0.0.7'));
  assert.ok(!salida.includes('usr-42'));
});
