import { test } from 'node:test';
import assert from 'node:assert/strict';
import { crearAleatorio } from './aleatorio.js';
import { extraerCaracteristicas, describirCaracteristicas, recorrerFlujo, DIMENSION } from './caracteristicas.js';
import { entrenar, puntuar, serializar, deserializar, c } from './isolationForest.js';
import { generarTraficoNormal, generarAtaque, generarTraficoMixto, hashCuenta, hashIp, INICIO_POR_DEFECTO } from './generadorTrafico.js';
import {
  crearDetector, entrenarDetectorPorDefecto, serializarModelo, deserializarModelo, aRiesgoContrato,
} from './detector.js';

const detector = entrenarDetectorPorDefecto(42);
const DIEZ_AM = INICIO_POR_DEFECTO + 10 * 3600 * 1000;

/** Nube gaussiana 2D alrededor del origen. */
function nubeNormal(semilla, n = 500) {
  const azar = crearAleatorio(semilla);
  return Array.from({ length: n }, () => [azar.normal(0, 1), azar.normal(0, 1)]);
}

/** Evalúa el último intento de un flujo con todos los anteriores como historial. */
function evaluarUltimo(det, eventos) {
  const ultimo = eventos.at(-1);
  const { resultado, ...intento } = ultimo;
  return det.evaluar(intento, eventos.slice(0, -1), ultimo.ts);
}

test('c(n) estándar de Liu et al.', () => {
  assert.equal(c(1), 0);
  assert.equal(c(2), 1);
  assert.ok(Math.abs(c(256) - 10.2448) < 1e-3);
});

test('determinismo: misma semilla produce el mismo PRNG, tráfico y modelo', () => {
  const a = crearAleatorio('semilla');
  const b = crearAleatorio('semilla');
  assert.deepEqual(Array.from({ length: 5 }, a.siguiente), Array.from({ length: 5 }, b.siguiente));

  assert.deepEqual(generarTraficoNormal({ semilla: 3, usuarios: 20 }), generarTraficoNormal({ semilla: 3, usuarios: 20 }));
  assert.deepEqual(generarTraficoMixto({ semilla: 3, usuarios: 20, campanasPorTipo: 1 }), generarTraficoMixto({ semilla: 3, usuarios: 20, campanasPorTipo: 1 }));

  const datos = nubeNormal(1);
  assert.equal(serializar(entrenar(datos, { semilla: 9 })), serializar(entrenar(datos, { semilla: 9 })));
  assert.notEqual(serializar(entrenar(datos, { semilla: 9 })), serializar(entrenar(datos, { semilla: 10 })));
  assert.equal(serializarModelo(entrenarDetectorPorDefecto(42).modelo), serializarModelo(detector.modelo));
});

test('Isolation Forest: puntos normales puntúan por debajo de los outliers', () => {
  const modelo = entrenar(nubeNormal(2), { arboles: 100, muestra: 256, semilla: 5 });
  const normales = [[0, 0], [0.3, -0.2], [-0.5, 0.4], [0.1, 0.8]].map((x) => puntuar(modelo, x));
  const outliers = [[6, 6], [-7, 5], [0, 9], [8, -8]].map((x) => puntuar(modelo, x));
  for (const s of [...normales, ...outliers]) assert.ok(s > 0 && s <= 1);
  assert.ok(Math.max(...normales) < Math.min(...outliers), `${normales} vs ${outliers}`);
  assert.ok(Math.max(...normales) < 0.5);
  assert.ok(Math.min(...outliers) > 0.6);
});

test('serializar/deserializar conserva las puntuaciones', () => {
  const modelo = entrenar(nubeNormal(3), { semilla: 1 });
  const copia = deserializar(serializar(modelo));
  for (const x of [[0, 0], [3, -2], [9, 9]]) assert.equal(puntuar(copia, x), puntuar(modelo, x));
  assert.throws(() => deserializar('{"tipo":"otro"}'));

  const det2 = crearDetector({ modelo: deserializarModelo(serializarModelo(detector.modelo)) });
  const ataque = generarAtaque('password_spraying', { inicio: DIEZ_AM });
  const original = evaluarUltimo(detector, ataque);
  const recargado = evaluarUltimo(det2, ataque);
  assert.equal(recargado.riskScore, original.riskScore);
  assert.deepEqual(recargado.reasons, original.reasons);
});

test('características: conteos de la ventana de 15 minutos', () => {
  const ahora = DIEZ_AM;
  const historial = [
    { user_ref_hash: 'A', ip_hash: 'ip1', resultado: 'invalid_code', ts: ahora - 60_000 },
    { user_ref_hash: 'A', ip_hash: 'ip2', resultado: 'invalid_code', ts: ahora - 30_000 },
    { user_ref_hash: 'B', ip_hash: 'ip1', resultado: 'ok', ts: new Date(ahora - 20_000).toISOString() },
    { user_ref_hash: 'A', ip_hash: 'ip3', resultado: 'invalid_code', ts: ahora - 20 * 60_000 }, // fuera de ventana
  ];
  const x = describirCaracteristicas(extraerCaracteristicas({ user_ref_hash: 'A', ip_hash: 'ip1' }, historial, ahora));
  assert.equal(Object.keys(x).length, DIMENSION);
  assert.equal(x.fallosCuenta15m, 2);
  assert.equal(x.ipsPorCuenta15m, 2);
  assert.equal(x.cuentasPorIp15m, 2);
  assert.equal(x.fallosIp15m, 1);
  assert.equal(x.intervaloMedioIp, 30);
  assert.equal(x.proporcionFallosIp, 0.5);
  assert.ok(Math.abs(x.horaSeno ** 2 + x.horaCoseno ** 2 - 1) < 1e-12);
  assert.ok(Math.abs(x.desviacionHora - (1 - Math.cos(Math.PI / 4)) / 2) < 1e-9); // 10:00 frente a 13:00 = 45°
});

test('detector: nivel alto en fuerza bruta distribuida y password spraying', () => {
  for (const tipo of ['fuerza_bruta_distribuida', 'password_spraying', 'fuerza_bruta_lenta']) {
    const r = evaluarUltimo(detector, generarAtaque(tipo, { inicio: DIEZ_AM, semilla: 4 }));
    assert.equal(r.level, 'alto', `${tipo}: ${JSON.stringify(r)}`);
    assert.equal(r.action, 'bloqueo_temporal');
    assert.ok(r.riskScore >= 75 && r.riskScore <= 100);
    assert.ok(r.reasons.length > 0 && r.reasons.every((s) => typeof s === 'string'));
  }
  const spray = evaluarUltimo(detector, generarAtaque('password_spraying', { inicio: DIEZ_AM }));
  assert.ok(spray.reasons.some((s) => s.includes('password spraying')));
  const distribuida = evaluarUltimo(detector, generarAtaque('fuerza_bruta_distribuida', { inicio: DIEZ_AM }));
  assert.ok(distribuida.reasons.some((s) => s.includes('hashes de IP')));
});

test('detector: nivel bajo para un usuario legítimo (un fallo y luego acierto)', () => {
  const cuenta = hashCuenta(1);
  const ip = hashIp('casa', 1);
  const historial = [{ user_ref_hash: cuenta, ip_hash: ip, resultado: 'invalid_code', ts: DIEZ_AM - 25_000 }];
  const r = detector.evaluar({ user_ref_hash: cuenta, ip_hash: ip, ts: DIEZ_AM }, historial, DIEZ_AM);
  assert.equal(r.level, 'bajo');
  assert.equal(r.action, 'permitir');
  assert.ok(r.riskScore < 60);
  assert.equal(typeof r.inferenceMs, 'number');
  assert.deepEqual(Object.keys(r).sort(), ['action', 'inferenceMs', 'level', 'reasons', 'riskScore']);
  assert.deepEqual(aRiesgoContrato(r).action, 'ALLOW');
});

test('detector: cede al bloqueo progresivo con una cuenta y un origen por debajo de 5 fallos (#65)', () => {
  const cuenta = hashCuenta(2);
  const ip = hashIp('casa', 2);
  const tarde = INICIO_POR_DEFECTO + 21 * 3600 * 1000; // hora inusual: suma riesgo
  const fallos = (n) => Array.from({ length: n }, (_, i) => ({ user_ref_hash: cuenta, ip_hash: ip, resultado: 'invalid_code', ts: tarde - (n - i) * 400 }));
  for (const n of [1, 2, 3, 4]) {
    const r = detector.evaluar({ user_ref_hash: cuenta, ip_hash: ip, ts: tarde }, fallos(n), tarde);
    assert.notEqual(r.action, 'bloqueo_temporal', `${n} fallos: ${JSON.stringify(r)}`);
    if (r.level !== 'bajo') {
      assert.equal(r.cedidoAlProgresivo, true);
      assert.ok(r.reasons.some((s) => s.includes('bloqueo progresivo')));
    }
  }
  // Con 3 fallos rápidos y hora inusual el riesgo es alto, pero solo se retrasa.
  const tres = detector.evaluar({ user_ref_hash: cuenta, ip_hash: ip, ts: tarde }, fallos(3), tarde);
  assert.equal(tres.level, 'alto', JSON.stringify(tres));
  assert.equal(tres.action, 'espera_extra');
  assert.equal(aRiesgoContrato(tres).action, 'DELAY');
  // Desde el umbral (5 fallos) el detector vuelve a poder bloquear.
  const cinco = detector.evaluar({ user_ref_hash: cuenta, ip_hash: ip, ts: tarde }, fallos(5), tarde);
  assert.equal(cinco.action, 'bloqueo_temporal');
  assert.equal(cinco.cedidoAlProgresivo, undefined);
  // Con una segunda IP o una segunda cuenta en juego no hay cesión.
  const otraIp = [...fallos(3), { user_ref_hash: cuenta, ip_hash: hashIp('otra', 9), resultado: 'invalid_code', ts: tarde - 100 }];
  assert.equal(detector.evaluar({ user_ref_hash: cuenta, ip_hash: ip, ts: tarde }, otraIp, tarde).cedidoAlProgresivo, undefined);
  const otraCuenta = [...fallos(3), { user_ref_hash: hashCuenta(3), ip_hash: ip, resultado: 'invalid_code', ts: tarde - 100 }];
  assert.equal(detector.evaluar({ user_ref_hash: cuenta, ip_hash: ip, ts: tarde }, otraCuenta, tarde).cedidoAlProgresivo, undefined);
  // Se puede desactivar (maxFallosCuenta 0): vuelve el comportamiento anterior.
  const sinCesion = crearDetector({ modelo: detector.modelo, reglas: { cederAlProgresivo: { maxFallosCuenta: 0 } } });
  assert.equal(sinCesion.evaluar({ user_ref_hash: cuenta, ip_hash: ip, ts: tarde }, fallos(3), tarde).action, 'bloqueo_temporal');
});

test('modo monitorización nunca bloquea, solo alerta', () => {
  const monitor = crearDetector({ modelo: detector.modelo, modo: 'monitorizacion' });
  const acciones = new Set();
  recorrerFlujo(generarAtaque('fuerza_bruta_distribuida', { inicio: DIEZ_AM }), (_e, intento, historial, ahora) => {
    acciones.add(monitor.evaluar(intento, historial, ahora).action);
  });
  assert.ok(acciones.has('alerta'));
  assert.ok(!acciones.has('bloqueo_temporal') && !acciones.has('espera_extra'));
  const r = evaluarUltimo(monitor, generarAtaque('password_spraying', { inicio: DIEZ_AM }));
  assert.equal(r.level, 'alto');
  assert.equal(r.action, 'alerta');
  assert.throws(() => crearDetector({ modelo: detector.modelo, modo: 'otro' }));
});

test('latencia de inferencia p95 < 15 ms', () => {
  const latencias = [];
  const flujo = generarTraficoMixto({ semilla: 8, usuarios: 100, dias: 1, campanasPorTipo: 3 });
  recorrerFlujo(flujo, (_e, intento, historial, ahora) => latencias.push(detector.evaluar(intento, historial, ahora).inferenceMs));
  latencias.sort((a, b) => a - b);
  const p95 = latencias[Math.floor(0.95 * (latencias.length - 1))];
  assert.ok(latencias.length > 200);
  assert.ok(p95 < 15, `p95 = ${p95} ms`);
});
