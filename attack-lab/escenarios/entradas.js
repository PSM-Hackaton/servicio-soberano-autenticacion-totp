#!/usr/bin/env node
// Escenario: entradas malformadas. JSON roto, campos extra, tipos incorrectos, cuerpos enormes,
// contaminación de prototipo, rutas raras, métodos no permitidos, credenciales ausentes...
// Esperado: SIEMPRE 4xx con el error genérico { error, message }, nunca 5xx ni rastros internos
// (pilas, rutas de archivos, mensajes de SQLite), y el servicio sigue sano al terminar.

import { esPrincipal, exigirCredenciales, principal, sondearSalud } from '../lib/escenario.js';
import { etiquetaEstado } from '../lib/http.js';
import { distribucionEstados, resumenLatencias } from '../lib/metricas.js';
import { filtraDetallesInternos } from '../lib/servicio.js';

export const id = 'entradas';
export const nombre = 'Entradas malformadas';
export const demuestra = 'Campos extra, tipos incorrectos, JSON roto o cuerpos enormes se rechazan con 4xx genérico, sin errores internos ni filtraciones.';

const UUID = '00000000-0000-4000-8000-000000000000';

/** @returns {{ d: string, m: string, r: string, op?: any, esperado?: number[] }[]} */
function casos() {
  const ok = { user_ref: 'lab-entradas', code: '123456' };
  const anidado = `${'{"a":'.repeat(5000)}{}${'}'.repeat(5000)}`;
  return [
    { d: 'JSON malformado', m: 'POST', r: '/api/v1/verify', op: { crudo: '{"user_ref": "x", "code": ' }, esperado: [400] },
    { d: 'Cuerpo vacío con Content-Type JSON', m: 'POST', r: '/api/v1/verify', op: { crudo: '' }, esperado: [400] },
    { d: 'Arreglo en lugar de objeto', m: 'POST', r: '/api/v1/verify', op: { cuerpo: [ok] }, esperado: [400] },
    { d: 'Campo extra (additionalProperties:false)', m: 'POST', r: '/api/v1/verify', op: { cuerpo: { ...ok, admin: true } }, esperado: [400] },
    { d: 'code numérico en vez de texto', m: 'POST', r: '/api/v1/verify', op: { cuerpo: { user_ref: 'lab-x', code: 123456 } }, esperado: [400] },
    { d: 'user_ref objeto', m: 'POST', r: '/api/v1/verify', op: { cuerpo: { user_ref: { $ne: null }, code: '123456' } }, esperado: [400] },
    { d: 'code con letras', m: 'POST', r: '/api/v1/verify', op: { cuerpo: { user_ref: 'lab-x', code: '12a456' } }, esperado: [400] },
    { d: 'code de 9 dígitos', m: 'POST', r: '/api/v1/verify', op: { cuerpo: { user_ref: 'lab-x', code: '123456789' } }, esperado: [400] },
    { d: 'user_ref de 10 000 caracteres', m: 'POST', r: '/api/v1/verify', op: { cuerpo: { user_ref: 'a'.repeat(10000), code: '123456' } }, esperado: [400, 413] },
    { d: 'Faltan campos obligatorios', m: 'POST', r: '/api/v1/verify', op: { cuerpo: { code: '123456' } }, esperado: [400] },
    { d: 'Contaminación de prototipo (__proto__)', m: 'POST', r: '/api/v1/verify', op: { crudo: '{"__proto__":{"admin":true},"user_ref":"lab-x","code":"123456"}' }, esperado: [400] },
    { d: 'constructor.prototype', m: 'POST', r: '/api/v1/verify', op: { crudo: '{"constructor":{"prototype":{"x":1}},"user_ref":"lab-x","code":"123456"}' }, esperado: [400] },
    { d: 'Caracteres de control / NUL en user_ref', m: 'POST', r: '/api/v1/verify', op: { cuerpo: { user_ref: 'lab\u0000\u001b[31m', code: '123456' } }, esperado: [400, 401] },
    { d: 'Inyección SQL en user_ref', m: 'POST', r: '/api/v1/verify', op: { cuerpo: { user_ref: "x' OR '1'='1' --", code: '123456' } }, esperado: [401, 400] },
    { d: 'JSON anidado 5 000 niveles', m: 'POST', r: '/api/v1/verify', op: { crudo: anidado }, esperado: [400, 413] },
    { d: 'Cuerpo enorme (2 MiB) con Content-Length', m: 'POST', r: '/api/v1/verify', op: { crudo: Buffer.alloc(2 * 1024 * 1024, 0x61) }, esperado: [413] },
    { d: 'Cuerpo enorme (2 MiB) en chunked', m: 'POST', r: '/api/v1/verify', op: { crudo: Buffer.alloc(2 * 1024 * 1024, 0x61), sinLongitud: true }, esperado: [413] },
    { d: 'Content-Type text/plain', m: 'POST', r: '/api/v1/verify', op: { crudo: JSON.stringify(ok), cabeceras: { 'content-type': 'text/plain' } }, esperado: [415, 400] },
    { d: 'Charset no UTF-8', m: 'POST', r: '/api/v1/verify', op: { crudo: JSON.stringify(ok), cabeceras: { 'content-type': 'application/json; charset=latin1' } }, esperado: [415, 400] },
    { d: 'Sin credenciales de app', m: 'POST', r: '/api/v1/verify', op: { cuerpo: ok, sinCredenciales: true }, esperado: [401] },
    { d: 'Secreto de app incorrecto', m: 'POST', r: '/api/v1/verify', op: { cuerpo: ok, cabeceras: { 'x-client-secret': 'secreto-incorrecto' } }, esperado: [401] },
    { d: 'client_id con caracteres raros', m: 'POST', r: '/api/v1/verify', op: { cuerpo: ok, cabeceras: { 'x-client-id': "' OR 1=1 --" } }, esperado: [401] },
    { d: 'Idempotency-Key inválida', m: 'POST', r: '/api/v1/verify', op: { cuerpo: ok, cabeceras: { 'idempotency-key': '<script>' } }, esperado: [400] },
    { d: 'Enrolamiento: algoritmo no permitido', m: 'POST', r: '/api/v1/enrollments', op: { cuerpo: { user_ref: 'lab-x', algorithm: 'MD5' } }, esperado: [400] },
    { d: 'Enrolamiento: periodo fuera de rango', m: 'POST', r: '/api/v1/enrollments', op: { cuerpo: { user_ref: 'lab-x', period: 1 } }, esperado: [400] },
    { d: 'Enrolamiento: digits = 7', m: 'POST', r: '/api/v1/enrollments', op: { cuerpo: { user_ref: 'lab-x', digits: 7 } }, esperado: [400] },
    { d: 'Activar: id que no es UUID', m: 'POST', r: '/api/v1/enrollments/no-es-uuid/activate', op: { cuerpo: { code: '123456' } }, esperado: [400, 401, 404] },
    { d: 'Activar: recorrido de rutas', m: 'POST', r: '/api/v1/enrollments/..%2F..%2Fadmin/activate', op: { cuerpo: { code: '123456' } }, esperado: [400, 401, 404] },
    { d: 'Activar: UUID inexistente', m: 'POST', r: `/api/v1/enrollments/${UUID}/activate`, op: { cuerpo: { code: '123456' } }, esperado: [401, 404] },
    { d: 'validate: token no texto', m: 'POST', r: '/api/v1/tokens/validate', op: { cuerpo: { token: { alg: 'none' } } }, esperado: [400] },
    { d: 'validate: consume_jti no booleano', m: 'POST', r: '/api/v1/tokens/validate', op: { cuerpo: { token: 'a.b.c', consume_jti: 'no' } }, esperado: [400] },
    { d: 'recovery: código demasiado corto', m: 'POST', r: '/api/v1/recovery', op: { cuerpo: { user_ref: 'lab-x', recovery_code: '1' } }, esperado: [400] },
    { d: 'Método no permitido (PUT /api/v1/verify)', m: 'PUT', r: '/api/v1/verify', op: { cuerpo: ok }, esperado: [405] },
    { d: 'Ruta inexistente', m: 'GET', r: '/api/v1/no-existe', op: {}, esperado: [404] },
    { d: 'Recorrido de rutas en estáticos', m: 'GET', r: '/app/..%2F..%2F..%2Fetc%2Fpasswd', op: { sinCredenciales: true }, esperado: [400, 403, 404] },
    { d: 'Consola admin sin sesión', m: 'GET', r: '/admin/api/apps', op: { sinCredenciales: true }, esperado: [401] },
    { d: 'Admin login: campo extra', m: 'POST', r: '/admin/api/login', op: { cuerpo: { usuario: 'a', password: 'b', rol: 'Administrador' }, sinCredenciales: true }, esperado: [400] },
  ];
}

export async function ejecutar(ctx, res) {
  exigirCredenciales(ctx);
  const { cliente } = ctx;
  const origen = {};
  const respuestas = [];
  for (const c of casos()) {
    const r = await cliente.peticion(c.m, c.r, { ...origen, ...c.op, timeoutMs: 8000 });
    respuestas.push(r);
    const genericoOk = r.status === 0 || (r.cuerpo && typeof r.cuerpo.error === 'string' && typeof r.cuerpo.message === 'string');
    const filtra = filtraDetallesInternos(r.texto);
    // Un cuerpo enorme puede acabar con el servidor cortando la conexión tras responder: no es un fallo.
    const conexionCortada = r.status === 0 && /ECONNRESET|EPIPE/.test(String(r.error)) && (c.esperado ?? []).includes(413);
    const ok = (conexionCortada || (r.status >= 400 && r.status < 500)) && genericoOk && !filtra;
    const esperadoTxt = (c.esperado ?? []).join('/') || '4xx';
    const extra = r.status >= 400 && !(c.esperado ?? []).includes(r.status) ? ' (4xx distinto del previsto)' : '';
    res.verificar(c.d, esperadoTxt, `${etiquetaEstado(r)}${conexionCortada ? ' (conexión cerrada)' : ''}${extra}${filtra ? ' ¡detalles internos!' : ''}${!genericoOk ? ' ¡sin error genérico!' : ''}`, ok);
    if (r.status >= 500) res.hallazgo(`${c.m} ${c.r} (${c.d}) provoca ${r.status}.`);
    if (filtra) res.hallazgo(`${c.m} ${c.r} (${c.d}) filtra detalles internos en la respuesta.`);
  }

  // Cabeceras de seguridad en una respuesta de la API.
  const muestra = await cliente.peticion('POST', '/api/v1/verify', { ...origen, cuerpo: { user_ref: 'lab-x', code: '000000' } });
  const h = muestra.cabeceras;
  const presentes = ['strict-transport-security', 'x-content-type-options', 'content-security-policy', 'referrer-policy'].filter((c) => h[c]);
  res.verificar('Cabeceras de seguridad (HSTS, nosniff, CSP, Referrer-Policy)', '4 de 4', `${presentes.length} de 4`, presentes.length === 4);
  res.verificar('Sin cabecera X-Powered-By', 'ausente', h['x-powered-by'] ?? 'ausente', !h['x-powered-by']);

  const salud = await sondearSalud(cliente);
  res.verificar('Servicio sano tras las entradas', '/health 200', etiquetaEstado(salud), salud.status === 200);
  res.metrica('casos', respuestas.length);
  res.metrica('estados', distribucionEstados(respuestas));
  res.metrica('latencia', resumenLatencias(respuestas.map((r) => r.ms)));
}

export default { id, nombre, demuestra, ejecutar };
if (esPrincipal(import.meta.url)) await principal({ id, nombre, demuestra, ejecutar });
