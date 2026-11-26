import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  hashSecreto, verificarSecreto, hashSecretoAsync, verificarSecretoAsync, generarSecretoCliente, generarClientId,
  generarCodigosRecuperacion, normalizarCodigoRecuperacion, ALFABETO_RECUPERACION,
  calcularBloqueo, bloqueadoHasta, estaBloqueado,
  crearLimitador, validarCuerpo, cabecerasSeguridad, errorGenerico,
} from './index.js';

// ── Secretos ────────────────────────────────────────────────────────────────

test('hashSecreto produce el formato scrypt$N$r$p$salt$hash con salt aleatorio', () => {
  const h1 = hashSecreto('clave-correcta');
  const h2 = hashSecreto('clave-correcta');
  const partes = h1.split('$');
  assert.equal(partes.length, 6);
  assert.deepEqual(partes.slice(0, 4), ['scrypt', '16384', '8', '1']);
  assert.equal(Buffer.from(partes[4], 'base64').length, 16);
  assert.equal(Buffer.from(partes[5], 'base64').length, 32);
  assert.notEqual(h1, h2, 'el salt debe variar');
});

test('verificarSecreto acepta el correcto y rechaza el incorrecto', () => {
  const h = hashSecreto('clave-correcta');
  assert.equal(verificarSecreto('clave-correcta', h), true);
  assert.equal(verificarSecreto('clave-incorrecta', h), false);
  assert.equal(verificarSecreto('', h), false);
  assert.equal(verificarSecreto(/** @type {any} */ (null), h), false);
});

test('verificarSecreto devuelve false ante formatos rotos sin lanzar', () => {
  const h = hashSecreto('x');
  const [, , , , salt, hash] = h.split('$');
  const rotos = [
    undefined, null, 42, '', 'texto', 'scrypt$16384$8$1$abc', `bcrypt$16384$8$1$${salt}$${hash}`,
    `scrypt$1000$8$1$${salt}$${hash}`, // N no potencia de 2
    `scrypt$${2 ** 24}$8$1$${salt}$${hash}`, // N excesivo (anti DoS)
    `scrypt$16384$0$1$${salt}$${hash}`, `scrypt$16384$8$1$%%%$${hash}`,
    `scrypt$16384$8$1$${salt}$${Buffer.alloc(4).toString('base64')}`, // hash demasiado corto
    `${h}$extra`,
  ];
  for (const r of rotos) assert.equal(verificarSecreto('x', /** @type {any} */ (r)), false, String(r));
});

test('variantes asíncronas son compatibles con las síncronas', async () => {
  const h = await hashSecretoAsync('abc');
  assert.equal(verificarSecreto('abc', h), true);
  assert.equal(await verificarSecretoAsync('abc', hashSecreto('abc')), true);
  assert.equal(await verificarSecretoAsync('abd', h), false);
  assert.equal(await verificarSecretoAsync('abc', 'roto'), false);
});

test('generarSecretoCliente y generarClientId', () => {
  const s = generarSecretoCliente();
  assert.match(s, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(Buffer.from(s, 'base64url').length, 32);
  assert.notEqual(s, generarSecretoCliente());
  assert.match(generarClientId('portal'), /^portal_[0-9a-f]{32}$/);
  assert.match(generarClientId(), /^app_[0-9a-f]{32}$/);
  assert.throws(() => generarClientId('Mal Prefijo'), TypeError);
});

// ── Códigos de recuperación ─────────────────────────────────────────────────

test('generarCodigosRecuperacion: 10 únicos, formato XXXX-XXXX y alfabeto sin ambiguos', () => {
  const codigos = generarCodigosRecuperacion();
  assert.equal(codigos.length, 10);
  assert.equal(new Set(codigos).size, 10);
  for (const c of codigos) {
    assert.match(c, /^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
    for (const ch of c.replace('-', '')) assert.ok(ALFABETO_RECUPERACION.includes(ch));
    assert.doesNotMatch(c, /[01OIL]/);
  }
  assert.equal(generarCodigosRecuperacion(3).length, 3);
  assert.throws(() => generarCodigosRecuperacion(0), RangeError);
});

test('normalizarCodigoRecuperacion tolera minúsculas, espacios y guiones', () => {
  assert.equal(normalizarCodigoRecuperacion('abcd-efgh'), 'ABCD-EFGH');
  assert.equal(normalizarCodigoRecuperacion(' abcd efgh '), 'ABCD-EFGH');
  assert.equal(normalizarCodigoRecuperacion('ABCDEFGH'), 'ABCD-EFGH');
  assert.equal(normalizarCodigoRecuperacion('ABCD-EFG0'), null, 'carácter ambiguo');
  assert.equal(normalizarCodigoRecuperacion('ABC'), null);
  assert.equal(normalizarCodigoRecuperacion(/** @type {any} */ (12345678)), null);
  const [c] = generarCodigosRecuperacion(1);
  const h = hashSecreto(c);
  assert.equal(verificarSecreto(normalizarCodigoRecuperacion(c.toLowerCase()), h), true);
});

// ── Bloqueo progresivo ──────────────────────────────────────────────────────

test('calcularBloqueo sube escalones cada maxIntentos fallos', () => {
  const casos = [[0, 0], [4, 0], [5, 30], [9, 30], [10, 120], [14, 120], [15, 600], [19, 600], [20, 3600], [100, 3600]];
  for (const [fallos, esperado] of casos) assert.equal(calcularBloqueo(fallos), esperado, `fallos=${fallos}`);
  assert.equal(calcularBloqueo(-1), 0);
  assert.equal(calcularBloqueo(3, { maxIntentos: 3, escalones: [10, 20] }), 10);
  assert.equal(calcularBloqueo(30, { maxIntentos: 3, escalones: [10, 20] }), 20);
});

test('estaBloqueado y bloqueadoHasta', () => {
  const ahora = Date.parse('2026-01-01T00:00:00Z');
  assert.equal(estaBloqueado(null, ahora), false);
  assert.equal(estaBloqueado('no-es-fecha', ahora), false);
  assert.equal(estaBloqueado('2026-01-01T00:00:30Z', ahora), true);
  assert.equal(estaBloqueado('2025-12-31T23:59:59Z', ahora), false);
  assert.equal(bloqueadoHasta(4, ahora), null);
  assert.equal(bloqueadoHasta(5, ahora), '2026-01-01T00:00:30.000Z');
});

// ── Limitador de tasa ───────────────────────────────────────────────────────

test('limitador permite la capacidad y luego bloquea', () => {
  const lim = crearLimitador({ capacidad: 3, ventanaMs: 60000 });
  const t = 1_000_000;
  assert.deepEqual(lim.consumir('ip1', t), { permitido: true, restantes: 2, reintentarEnMs: 0 });
  assert.equal(lim.consumir('ip1', t).restantes, 1);
  assert.equal(lim.consumir('ip1', t).restantes, 0);
  const r = lim.consumir('ip1', t);
  assert.equal(r.permitido, false);
  assert.equal(r.reintentarEnMs, 20000);
  assert.equal(lim.consumir('ip2', t).permitido, true, 'las claves son independientes');
});

test('limitador se recupera tras la ventana', () => {
  const lim = crearLimitador({ capacidad: 2, ventanaMs: 1000 });
  lim.consumir('k', 0); lim.consumir('k', 0);
  assert.equal(lim.consumir('k', 100).permitido, false);
  assert.equal(lim.consumir('k', 600).permitido, true, 'repone una ficha cada 500 ms');
  assert.equal(lim.consumir('k', 3000).restantes, 1, 'tras la ventana vuelve a estar lleno');
  lim.reiniciar('k');
  assert.equal(lim.tamano, 0);
});

test('limitador respeta maxClaves y limpia claves inactivas', () => {
  const lim = crearLimitador({ capacidad: 1, ventanaMs: 1000, maxClaves: 3 });
  for (const k of ['a', 'b', 'c', 'd', 'e']) lim.consumir(k, 0);
  assert.equal(lim.tamano, 3);
  lim.consumir('f', 500);
  lim.limpiar(1200);
  assert.equal(lim.tamano, 1, 'solo queda la clave usada en la última ventana');
  assert.throws(() => lim.consumir('', 0), TypeError);
  assert.throws(() => crearLimitador({ capacidad: 0, ventanaMs: 1 }), RangeError);
});

// ── Validación estricta ─────────────────────────────────────────────────────

const ESQUEMA_VERIFY = {
  type: 'object',
  required: ['enrollment_id', 'code'],
  properties: {
    enrollment_id: { type: 'string', pattern: '^[0-9a-f-]{36}$' },
    code: { type: 'string', pattern: '^[0-9]{6,8}$' },
    digitos: { type: 'integer', minimum: 6, maximum: 8 },
    algoritmo: { type: 'string', enum: ['SHA256', 'SHA512'] },
    recordar: { type: 'boolean' },
    contexto: { type: 'object', properties: { ua: { type: 'string', maxLength: 10 } } },
  },
};
const ID = '123e4567-e89b-12d3-a456-426614174000';

test('validarCuerpo acepta un cuerpo válido', () => {
  const cuerpo = { enrollment_id: ID, code: '123456', digitos: 6, algoritmo: 'SHA256', recordar: true, contexto: { ua: 'x' } };
  const r = validarCuerpo(cuerpo, ESQUEMA_VERIFY);
  assert.equal(r.ok, true);
  assert.deepEqual(r.valor, cuerpo);
});

test('validarCuerpo rechaza campo extra, tipo incorrecto, pattern, enum, rango y requeridos', () => {
  const casos = [
    [{ enrollment_id: ID, code: '123456', extra: 1 }, 'extra', 'campo no permitido'],
    [{ enrollment_id: ID, code: 123456 }, 'code', 'debe ser texto'],
    [{ enrollment_id: ID, code: '12ab56' }, 'code', 'formato inválido'],
    [{ enrollment_id: ID, code: '123456', digitos: 7.5 }, 'digitos', 'debe ser entero'],
    [{ enrollment_id: ID, code: '123456', digitos: 9 }, 'digitos', 'máximo 8'],
    [{ enrollment_id: ID, code: '123456', algoritmo: 'SHA1' }, 'algoritmo', 'valor no permitido'],
    [{ enrollment_id: ID, code: '123456', recordar: 'true' }, 'recordar', 'debe ser booleano'],
    [{ enrollment_id: ID, code: '123456', contexto: { ua: 'x', otro: 1 } }, 'contexto.otro', 'campo no permitido'],
    [{ enrollment_id: ID, code: '123456', contexto: { ua: 'x'.repeat(11) } }, 'contexto.ua', 'longitud máxima 10'],
    [{ code: '123456' }, 'enrollment_id', 'requerido'],
  ];
  for (const [cuerpo, campo, motivo] of casos) {
    const r = validarCuerpo(cuerpo, ESQUEMA_VERIFY);
    assert.equal(r.ok, false, JSON.stringify(cuerpo));
    assert.ok(r.errores.some((e) => e.campo === campo && e.motivo === motivo), `${campo}: ${JSON.stringify(r.errores)}`);
  }
  for (const noObjeto of [null, [], 'texto', 1, new Date()]) assert.equal(validarCuerpo(noObjeto, ESQUEMA_VERIFY).ok, false);
});

test('validarCuerpo rechaza __proto__ y constructor sin contaminar prototipos', () => {
  const malicioso = JSON.parse(`{"enrollment_id":"${ID}","code":"123456","__proto__":{"admin":true}}`);
  const r = validarCuerpo(malicioso, ESQUEMA_VERIFY);
  assert.equal(r.ok, false);
  assert.ok(r.errores.some((e) => e.campo === '__proto__' && e.motivo === 'clave prohibida'));
  assert.equal(/** @type {any} */ ({}).admin, undefined);
  const r2 = validarCuerpo(JSON.parse(`{"enrollment_id":"${ID}","code":"123456","constructor":{}}`), ESQUEMA_VERIFY);
  assert.equal(r2.ok, false);
  // Aun si el esquema declarara "constructor", se rechaza.
  const r3 = validarCuerpo({ constructor: 'x' }, { type: 'object', properties: { constructor: { type: 'string' } } });
  assert.equal(r3.ok, false);
});

// ── Cabeceras y errores ─────────────────────────────────────────────────────

test('cabecerasSeguridad incluye las cabeceras obligatorias', () => {
  const c = cabecerasSeguridad();
  assert.equal(c['Strict-Transport-Security'], 'max-age=63072000; includeSubDomains');
  for (const d of ["default-src 'self'", "frame-ancestors 'none'", "object-src 'none'", "base-uri 'none'"]) {
    assert.ok(c['Content-Security-Policy'].includes(d), d);
  }
  assert.equal(c['X-Content-Type-Options'], 'nosniff');
  assert.equal(c['Referrer-Policy'], 'no-referrer');
  assert.equal(c['Cache-Control'], 'no-store');
  assert.equal(c['Cross-Origin-Opener-Policy'], 'same-origin');
  assert.ok(c['Permissions-Policy'].includes('camera=()'));
  c['Cache-Control'] = 'x';
  assert.equal(cabecerasSeguridad()['Cache-Control'], 'no-store', 'cada llamada devuelve un objeto nuevo');
});

test('errorGenerico sigue GenericError y no enumera usuarios', () => {
  const esperados = { credenciales: 401, codigo: 401, limite: 429, no_disponible: 503, entrada: 400 };
  for (const [tipo, status] of Object.entries(esperados)) {
    const e = errorGenerico(/** @type {any} */ (tipo));
    assert.equal(e.status, status);
    assert.equal(typeof e.cuerpo.error, 'string');
    assert.equal(typeof e.cuerpo.message, 'string');
    assert.doesNotMatch(e.cuerpo.message, /usuario|existe|no encontrado/i);
  }
  const l = errorGenerico('limite', { reintentarEnSegundos: 29.2 });
  assert.equal(l.cuerpo.retry_after_seconds, 30);
  assert.equal(l.cabeceras['Retry-After'], '30');
  assert.equal(errorGenerico(/** @type {any} */ ('raro')).status, 503);
});
