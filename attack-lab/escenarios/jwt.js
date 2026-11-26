#!/usr/bin/env node
// Escenario: manipulación de tokens MFA (JWT EdDSA). Se obtiene un JWT legítimo y se prueban
// variantes: alterado, firma rota, alg "none", confusión HS256, kid desconocido, caducado,
// otra audiencia y reutilización del jti. Todas deben rechazarse; el original, validarse una sola vez.
//
// Caducado: por defecto se FORJA un token caducado (firmado con una clave ajena, así que también
// lo rechaza la firma). Con --esperar-caducidad se espera de verdad TTL + tolerancia (≈5,5 min).
// Otra audiencia: con credenciales de una segunda app (--client-id-2/--client-secret-2) se valida el
// token de la app 1 con la app 2 (prueba real); sin ellas, se altera el claim aud.

import { createHmac, generateKeyPairSync, sign } from 'node:crypto';
import { crearUsuarioPrueba, esPrincipal, exigirCredenciales, principal } from '../lib/escenario.js';
import { etiquetaEstado } from '../lib/http.js';
import { codigoNuevo } from '../lib/totp.js';
import { dormir } from '../lib/metricas.js';
import { validarToken, verificarUsuario } from '../lib/servicio.js';
import { verifyMfaJwt } from '../../backend/src/core/tokens/tokens.js';

export const id = 'jwt';
export const nombre = 'Manipulación de JWT MFA';
export const demuestra = 'Un JWT alterado, con alg falso, caducado, de otra audiencia o ya usado es rechazado; el legítimo se valida una sola vez y también offline con JWKS.';

const b64 = (o) => Buffer.from(typeof o === 'string' ? o : JSON.stringify(o)).toString('base64url');
const decodificar = (p) => JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));

/** Rechazado = 200 { valid: false } o 4xx; nunca valid:true ni 5xx. */
const rechazado = (r) => (r.status === 200 && r.cuerpo?.valid === false) || (r.status >= 400 && r.status < 500);
const describir = (r) => (r.status === 200 ? `valid=${r.cuerpo?.valid}${r.cuerpo?.reason ? ` (${r.cuerpo.reason})` : ''}` : etiquetaEstado(r));

function firmarConClaveAjena(header, claims) {
  const { privateKey } = generateKeyPairSync('ed25519');
  const entrada = `${b64(header)}.${b64(claims)}`;
  return `${entrada}.${sign(null, Buffer.from(entrada), privateKey).toString('base64url')}`;
}

export async function ejecutar(ctx, res) {
  exigirCredenciales(ctx);
  const { cliente, cliente2, config } = ctx;
  const usuario = await crearUsuarioPrueba(ctx);
  const { codigo } = await codigoNuevo(usuario, { ventana: config.ventana });
  const v = await verificarUsuario(cliente, usuario, codigo);
  if (v.status !== 200 || !v.cuerpo?.token) throw new Error(`No se obtuvo un JWT legítimo (${etiquetaEstado(v)})`);
  const token = v.cuerpo.token;
  const [h64, p64, f64] = token.split('.');
  const header = decodificar(h64);
  const claims = decodificar(p64);
  res.metrica('JWT legítimo', `alg=${header.alg} kid=${header.kid} aud=${claims.aud} ttl=${claims.exp - claims.iat} s amr=${JSON.stringify(claims.amr)}`);

  // 0. Línea base sin consumir.
  const base = await validarToken(cliente, token, false);
  res.verificar('Token legítimo (sin consumir jti)', 'valid=true', describir(base), base.status === 200 && base.cuerpo?.valid === true);

  // 0b. Validación offline con JWKS (lo que hace un integrador sin llamar al servicio).
  const jwks = await cliente.get('/.well-known/jwks.json', { sinCredenciales: true });
  const offline = jwks.status === 200 ? verifyMfaJwt(token, { jwks: jwks.cuerpo, issuer: claims.iss, audience: claims.aud }) : { valid: false, reason: 'sin JWKS' };
  res.verificar('Validación offline con /.well-known/jwks.json', 'firma válida', offline.valid ? 'válida' : `inválida (${offline.reason})`, offline.valid);

  // Variantes manipuladas.
  const otroSub = { ...claims, sub: `${claims.sub.slice(0, -1)}${claims.sub.endsWith('A') ? 'B' : 'A'}` };
  const firmaRota = (() => {
    const bytes = Buffer.from(f64, 'base64url');
    bytes[10] ^= 0x01;
    return bytes.toString('base64url');
  })();
  const jwk = jwks.cuerpo?.keys?.find((k) => k.kid === header.kid);
  const hs256 = (() => {
    const hh = b64({ alg: 'HS256', typ: 'JWT', kid: header.kid });
    const entrada = `${hh}.${p64}`;
    return `${entrada}.${createHmac('sha256', String(jwk?.x ?? 'x')).update(entrada).digest('base64url')}`;
  })();
  const ahora = Math.floor(Date.now() / 1000);
  const variantes = [
    ['Payload alterado (otro sub, firma original)', `${h64}.${b64(otroSub)}.${f64}`],
    ['Firma alterada (1 bit)', `${h64}.${p64}.${firmaRota}`],
    ['alg "none" sin firma', `${b64({ alg: 'none', typ: 'JWT' })}.${p64}.`],
    ['Confusión de algoritmo HS256 (clave pública como secreto)', hs256],
    ['kid desconocido', `${b64({ ...header, kid: 'kid-inexistente' })}.${p64}.${f64}`],
    ['Token caducado (forjado, exp en el pasado)', firmarConClaveAjena(header, { ...claims, iat: ahora - 900, nbf: ahora - 900, exp: ahora - 600 })],
    ['Firmado con una clave ajena (mismo kid)', firmarConClaveAjena(header, claims)],
    ['Basura / no es un JWT', 'esto.no.es-un-jwt'],
  ];
  if (!cliente2) variantes.push(['Otra audiencia (claim aud alterado)', `${h64}.${b64({ ...claims, aud: 'otra-app' })}.${f64}`]);

  for (const [descripcion, t] of variantes) {
    const r = await validarToken(cliente, t, true);
    res.verificar(descripcion, 'rechazado', describir(r), rechazado(r));
    if (r.status === 200 && r.cuerpo?.valid === true) res.hallazgo(`JWT manipulado aceptado: ${descripcion}.`);
  }

  // Otra audiencia real: la app 2 valida el token emitido para la app 1.
  if (cliente2) {
    const r = await validarToken(cliente2, token, false);
    res.verificar('Otra audiencia (app 2 valida token de app 1)', 'rechazado (aud)', describir(r), rechazado(r));
    if (r.cuerpo?.valid === true) res.hallazgo('Un JWT emitido para una app es aceptado por otra app (audiencia no verificada).');
  } else {
    res.nota('Para probar "otra audiencia" con una segunda app real, pasa --client-id-2/--client-secret-2.');
  }

  // Reutilización del jti: primera validación consume, la segunda se rechaza.
  const uso1 = await validarToken(cliente, token, true);
  const uso2 = await validarToken(cliente, token, true);
  res.verificar('Primer uso del token (consume jti)', 'valid=true', describir(uso1), uso1.status === 200 && uso1.cuerpo?.valid === true);
  res.verificar('Reutilización del jti', 'rechazado (jti consumido)', describir(uso2), rechazado(uso2));
  if (uso2.cuerpo?.valid === true) res.hallazgo('El jti de un JWT MFA puede consumirse más de una vez.');

  // Caducidad real (opcional, lenta).
  if (config.opciones['esperar-caducidad']) {
    const c2 = await codigoNuevo(usuario, { ventana: config.ventana });
    const v2 = await verificarUsuario(cliente, usuario, c2.codigo);
    const cl2 = decodificar(v2.cuerpo.token.split('.')[1]);
    const espera = (cl2.exp + 32) * 1000 - Date.now();
    ctx.log(`esperando ${(espera / 1000).toFixed(0)} s a que caduque el token…`);
    await dormir(Math.max(0, espera));
    const r = await validarToken(cliente, v2.cuerpo.token, false);
    res.verificar('Token caducado de verdad (TTL + tolerancia)', 'rechazado (exp)', describir(r), rechazado(r));
  } else {
    res.nota('La caducidad real se prueba con --esperar-caducidad (espera TTL + 30 s de tolerancia).');
  }
}

export default { id, nombre, demuestra, ejecutar };
if (esPrincipal(import.meta.url)) await principal({ id, nombre, demuestra, ejecutar });
