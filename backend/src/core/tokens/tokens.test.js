import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, createPrivateKey, sign } from 'node:crypto';
import {
  generarParFirma, signMfaJwt, verifyMfaJwt, getPublicJwks, calcularKid, base64urlEncode, base64urlDecode,
} from './tokens.js';

const ISS = 'https://totp.soberano.local';
const AUD = 'portal-tramites';
const AHORA = Date.UTC(2026, 10, 26, 16, 0, 0);

const par = generarParFirma();
const jwks = getPublicJwks([par]);
const opcionesVerificacion = { jwks, issuer: ISS, audience: AUD, ahora: AHORA };

/** @param {object} [extra] */
function emitir(extra = {}) {
  return signMfaJwt({
    privateKey: par.privateKey, kid: par.kid, issuer: ISS, audience: AUD, subject: 'hmac_842b9c1e', ahora: AHORA, ...extra,
  });
}

/** Firma con Ed25519 un header y payload arbitrarios (para probar validaciones posteriores a la firma). */
function firmarCrudo(header, payload, clave = par.privateKey) {
  const entrada = `${base64urlEncode(JSON.stringify(header))}.${base64urlEncode(JSON.stringify(payload))}`;
  return `${entrada}.${base64urlEncode(sign(null, Buffer.from(entrada), clave))}`;
}

test('base64url: ida y vuelta y rechazo de entradas no canónicas', () => {
  for (const texto of ['', 'f', 'fo', 'foo', 'foob', 'fooba', 'foobar']) {
    assert.equal(base64urlDecode(base64urlEncode(texto)).toString(), texto);
  }
  assert.equal(base64urlEncode(Buffer.from([0xfb, 0xff])), '-_8');
  assert.equal(base64urlDecode('ab+c'), null);
  assert.equal(base64urlDecode('abc='), null);
  assert.equal(base64urlDecode('a'), null);
  assert.equal(base64urlDecode('-_9'), null, 'bits sobrantes distintos de cero');
});

test('generarParFirma: kid es el thumbprint truncado del JWK público', () => {
  assert.equal(par.kid, calcularKid(par.publicJwk));
  assert.match(par.kid, /^[A-Za-z0-9_-]{22}$/);
  assert.equal(par.privateKey.asymmetricKeyType, 'ed25519');
  // PEM PKCS#8: exportar de nuevo la llave produce exactamente el mismo texto.
  assert.equal(createPrivateKey(par.privatePem).export({ type: 'pkcs8', format: 'pem' }), par.privatePem);
  assert.equal(createPrivateKey(par.privatePem).asymmetricKeyType, 'ed25519');
  assert.notEqual(generarParFirma().kid, par.kid);
});

test('firma y verificación correctas con claims esperados', () => {
  const token = emitir({ extra: { sid: 'sesion-1' } });
  const [h] = token.split('.');
  assert.deepEqual(JSON.parse(base64urlDecode(h).toString()), { alg: 'EdDSA', typ: 'JWT', kid: par.kid });
  const r = verifyMfaJwt(token, opcionesVerificacion);
  assert.equal(r.valid, true);
  const iat = Math.floor(AHORA / 1000);
  assert.equal(r.claims.iss, ISS);
  assert.equal(r.claims.sub, 'hmac_842b9c1e');
  assert.equal(r.claims.aud, AUD);
  assert.deepEqual(r.claims.amr, ['otp']);
  assert.equal(r.claims.iat, iat);
  assert.equal(r.claims.nbf, iat);
  assert.equal(r.claims.exp, iat + 300);
  assert.equal(r.claims.sid, 'sesion-1');
  assert.match(r.claims.jti, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.notEqual(emitir().split('.')[1], emitir().split('.')[1], 'jti distinto en cada emisión');
});

test('extra no puede sobrescribir claims reservados', () => {
  const r = verifyMfaJwt(emitir({ extra: { iss: 'otro', aud: 'otra', exp: 1 } }), opcionesVerificacion);
  assert.equal(r.valid, true);
  assert.equal(r.claims.iss, ISS);
});

test('verificación con buscarClave(kid)', () => {
  const buscarClave = (kid) => (kid === par.kid ? par.publicJwk : null);
  assert.equal(verifyMfaJwt(emitir(), { buscarClave, issuer: ISS, audience: AUD, ahora: AHORA }).valid, true);
  const lanza = () => { throw new Error('fallo de almacén'); };
  assert.deepEqual(verifyMfaJwt(emitir(), { buscarClave: lanza, issuer: ISS, audience: AUD, ahora: AHORA }), { valid: false, reason: 'kid' });
});

test('firma alterada se rechaza', () => {
  const [h, p, f] = emitir().split('.');
  const bytes = base64urlDecode(f);
  bytes[0] ^= 0x01;
  assert.deepEqual(verifyMfaJwt(`${h}.${p}.${base64urlEncode(bytes)}`, opcionesVerificacion), { valid: false, reason: 'firma' });
  assert.deepEqual(verifyMfaJwt(`${h}.${p}.${base64urlEncode(bytes.subarray(0, 32))}`, opcionesVerificacion), { valid: false, reason: 'firma' });
});

test('payload alterado se rechaza', () => {
  const [h, p, f] = emitir().split('.');
  const claims = JSON.parse(base64urlDecode(p).toString());
  claims.sub = 'atacante';
  const alterado = `${h}.${base64urlEncode(JSON.stringify(claims))}.${f}`;
  assert.deepEqual(verifyMfaJwt(alterado, opcionesVerificacion), { valid: false, reason: 'firma' });
});

test('token caducado se rechaza (respetando la tolerancia)', () => {
  const token = emitir({ ttlSegundos: 60 });
  assert.equal(verifyMfaJwt(token, { ...opcionesVerificacion, ahora: AHORA + 60_000 + 29_000 }).valid, true);
  assert.deepEqual(verifyMfaJwt(token, { ...opcionesVerificacion, ahora: AHORA + 60_000 + 30_000 }), { valid: false, reason: 'exp' });
  assert.deepEqual(verifyMfaJwt(token, { ...opcionesVerificacion, ahora: AHORA + 61_000, toleranciaSegundos: 0 }), { valid: false, reason: 'exp' });
});

test('nbf en el futuro se rechaza', () => {
  const token = emitir({ ahora: AHORA + 120_000 });
  assert.deepEqual(verifyMfaJwt(token, opcionesVerificacion), { valid: false, reason: 'nbf' });
  assert.equal(verifyMfaJwt(emitir({ ahora: AHORA + 20_000 }), opcionesVerificacion).valid, true, 'dentro de la tolerancia');
});

test('otra audiencia y otro emisor se rechazan', () => {
  assert.deepEqual(verifyMfaJwt(emitir({ audience: 'otra-app' }), opcionesVerificacion), { valid: false, reason: 'aud' });
  assert.deepEqual(verifyMfaJwt(emitir({ issuer: 'https://impostor.local' }), opcionesVerificacion), { valid: false, reason: 'iss' });
});

test('kid desconocido o ausente se rechaza', () => {
  const otro = generarParFirma();
  const token = signMfaJwt({
    privateKey: otro.privateKey, kid: otro.kid, issuer: ISS, audience: AUD, subject: 's', ahora: AHORA,
  });
  assert.deepEqual(verifyMfaJwt(token, opcionesVerificacion), { valid: false, reason: 'kid' });
  const sinKid = firmarCrudo({ alg: 'EdDSA', typ: 'JWT' }, { iss: ISS, aud: AUD, exp: 9e9 });
  assert.deepEqual(verifyMfaJwt(sinKid, opcionesVerificacion), { valid: false, reason: 'kid' });
});

test("alg 'none' y HS256 se rechazan", () => {
  const claims = { iss: ISS, sub: 's', aud: AUD, exp: Math.floor(AHORA / 1000) + 300, jti: 'x' };
  const sinFirma = `${base64urlEncode(JSON.stringify({ alg: 'none', typ: 'JWT', kid: par.kid }))}.${base64urlEncode(JSON.stringify(claims))}.`;
  assert.equal(verifyMfaJwt(sinFirma, opcionesVerificacion).valid, false);
  const noneConFirma = `${sinFirma}${base64urlEncode(Buffer.alloc(64))}`;
  assert.deepEqual(verifyMfaJwt(noneConFirma, opcionesVerificacion), { valid: false, reason: 'alg' });

  // Confusión de algoritmo: HMAC usando la clave pública como secreto.
  const entrada = `${base64urlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: par.kid }))}.${base64urlEncode(JSON.stringify(claims))}`;
  const hmac = createHmac('sha256', JSON.stringify(par.publicJwk)).update(entrada).digest();
  assert.deepEqual(verifyMfaJwt(`${entrada}.${base64urlEncode(hmac)}`, opcionesVerificacion), { valid: false, reason: 'alg' });

  const ed25519Minusculas = firmarCrudo({ alg: 'eddsa', kid: par.kid }, claims);
  assert.deepEqual(verifyMfaJwt(ed25519Minusculas, opcionesVerificacion), { valid: false, reason: 'alg' });
});

test('tokens malformados se rechazan sin lanzar', () => {
  const token = emitir();
  const [h, p, f] = token.split('.');
  const casos = [
    '', '   ', 'abc', `${h}.${p}`, `${h}.${p}.${f}.extra`, `..`, `${h}..${f}`,
    `${h}.${p}.@@@`, `${h}.%%%.${f}`, `###.${p}.${f}`, `${h}=.${p}.${f}`,
    `${base64urlEncode('no es json')}.${p}.${f}`, `${base64urlEncode('[1,2]')}.${p}.${f}`,
    `${base64urlEncode('null')}.${p}.${f}`, 'x'.repeat(10_000), null, undefined, 42, {}, [],
  ];
  for (const caso of casos) {
    let r;
    assert.doesNotThrow(() => { r = verifyMfaJwt(caso, opcionesVerificacion); });
    assert.equal(r.valid, false, `caso ${String(caso).slice(0, 30)}`);
    assert.equal(r.reason, 'formato', `caso ${String(caso).slice(0, 30)}`);
  }
});

test('JWKS con formato del contrato y su clave verifica', () => {
  assert.equal(jwks.keys.length, 1);
  const [clave] = jwks.keys;
  assert.deepEqual(Object.keys(clave).sort(), ['alg', 'crv', 'kid', 'kty', 'use', 'x']);
  assert.equal(clave.kty, 'OKP');
  assert.equal(clave.crv, 'Ed25519');
  assert.equal(clave.use, 'sig');
  assert.equal(clave.alg, 'EdDSA');
  assert.equal(clave.kid, par.kid);
  assert.equal(base64urlDecode(clave.x).length, 32);
  assert.ok(!('d' in clave), 'el JWKS no expone material privado');
  // Simula un cliente que descarga el JWKS como JSON.
  const descargado = JSON.parse(JSON.stringify(jwks));
  assert.equal(verifyMfaJwt(emitir(), { ...opcionesVerificacion, jwks: descargado }).valid, true);
  // También acepta entradas { kid, x }.
  assert.deepEqual(getPublicJwks([{ kid: 'key-20261126-01', x: clave.x }]).keys[0].kid, 'key-20261126-01');
  assert.throws(() => getPublicJwks([{ kid: 'k', x: 'corta' }]));
});

test('JWK con curva o alg incompatibles no sirve para verificar', () => {
  const token = emitir();
  const [clave] = jwks.keys;
  for (const mala of [{ ...clave, crv: 'X25519' }, { ...clave, kty: 'EC' }, { ...clave, alg: 'HS256' }, { ...clave, use: 'enc' }]) {
    assert.deepEqual(verifyMfaJwt(token, { ...opcionesVerificacion, jwks: { keys: [mala] } }), { valid: false, reason: 'kid' });
  }
});

test('rotación: token firmado con la clave vieja verifica mientras su kid siga en el JWKS', () => {
  const vieja = par;
  const nueva = generarParFirma();
  const tokenViejo = emitir();
  const tokenNuevo = signMfaJwt({
    privateKey: nueva.privateKey, kid: nueva.kid, issuer: ISS, audience: AUD, subject: 's', ahora: AHORA,
  });
  const enGracia = getPublicJwks([nueva, vieja]);
  assert.equal(verifyMfaJwt(tokenViejo, { ...opcionesVerificacion, jwks: enGracia }).valid, true);
  assert.equal(verifyMfaJwt(tokenNuevo, { ...opcionesVerificacion, jwks: enGracia }).valid, true);
  const retirada = getPublicJwks([nueva]);
  assert.deepEqual(verifyMfaJwt(tokenViejo, { ...opcionesVerificacion, jwks: retirada }), { valid: false, reason: 'kid' });
  // Un kid válido apuntando a otra clave no permite suplantar.
  const cruzado = { keys: [{ ...enGracia.keys[0], kid: vieja.kid }] };
  assert.deepEqual(verifyMfaJwt(tokenViejo, { ...opcionesVerificacion, jwks: cruzado }), { valid: false, reason: 'firma' });
});
