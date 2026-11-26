// Pruebas de la validación estricta de URIs otpauth y del alta manual (js/otpauth.js).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ErrorCuenta, analizarOtpauth, construirOtpauth, extraerDeEnlace, validarCuenta } from '../js/otpauth.js';

const SECRETO = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // 20 bytes

test('acepta una URI completa del Portal y normaliza los datos', () => {
  const uri = `otpauth://totp/Portal%20de%20Tr%C3%A1mites:maria.perez?secret=${SECRETO}&issuer=Portal+de+Tr%C3%A1mites&algorithm=SHA256&digits=8&period=30`;
  assert.deepEqual(analizarOtpauth(uri), {
    emisor: 'Portal de Trámites', cuenta: 'maria.perez', secreto: SECRETO, algoritmo: 'SHA256', digitos: 8, periodo: 30,
  });
});

test('valores por omisión: SHA1, 6 dígitos y 30 s', () => {
  const r = analizarOtpauth(`otpauth://totp/cuenta?secret=${SECRETO.toLowerCase()}`);
  assert.equal(r.algoritmo, 'SHA1');
  assert.equal(r.digitos, 6);
  assert.equal(r.periodo, 30);
  assert.equal(r.emisor, '');
  assert.equal(r.cuenta, 'cuenta');
});

test('es compatible con buildOtpauthUri del backend', async () => {
  const { buildOtpauthUri } = await import('../../backend/src/core/totp/totp.js');
  const semilla = Buffer.from(crypto.getRandomValues(new Uint8Array(32)));
  const uri = buildOtpauthUri({ semilla, emisor: 'Portal de Trámites', cuenta: 'ana@ejemplo.gob', algoritmo: 'SHA256', digitos: 6, periodo: 30 });
  const r = analizarOtpauth(uri);
  assert.equal(r.emisor, 'Portal de Trámites');
  assert.equal(r.cuenta, 'ana@ejemplo.gob');
  assert.equal(r.algoritmo, 'SHA256');
});

test('rechaza URIs inseguras o mal formadas', () => {
  const malas = [
    ['https://evil.example/?secret=x', /otpauth:\/\/totp/],
    [`otpauth://hotp/x?secret=${SECRETO}&counter=1`, /HOTP/],
    [`otpauth://totp/x?secret=${SECRETO}&counter=1`, /HOTP/],
    ['otpauth://totp/x', /parámetros/],
    ['otpauth://totp/x?issuer=A', /clave/],
    [`otpauth://totp/x?secret=${SECRETO}&algorithm=MD5`, /Algoritmo/],
    [`otpauth://totp/x?secret=${SECRETO}&digits=7`, /6 u 8/],
    [`otpauth://totp/x?secret=${SECRETO}&period=10`, /entre 15 y 60/],
    [`otpauth://totp/x?secret=${SECRETO}&period=90`, /entre 15 y 60/],
    [`otpauth://totp/x?secret=${SECRETO}&period=30.5`, /entero/],
    [`otpauth://totp/x?secret=${SECRETO}&secret=${SECRETO}`, /repetido/],
    [`otpauth://totp/Banco:x?secret=${SECRETO}&issuer=Otro`, /no coincide/],
    ['otpauth://totp/x?secret=JBSWY3DPEHPK3PXP', /corta/],
    ['otpauth://totp/x?secret=ABC1DEF0', /A–Z/],
    [`otpauth://totp/%E0%A4%A?secret=${SECRETO}`, /codificada/],
    [`otpauth://totp/${'a'.repeat(3000)}?secret=${SECRETO}`, /larga/],
    [`otpauth://totp/:?secret=${SECRETO}`, /al menos/],
  ];
  for (const [uri, motivo] of malas) {
    assert.throws(() => analizarOtpauth(uri), (e) => e instanceof ErrorCuenta && motivo.test(e.message), uri.slice(0, 80));
  }
});

test('elimina caracteres invisibles y de control bidireccional en los nombres', () => {
  const r = analizarOtpauth(`otpauth://totp/Ban%E2%80%AEco:ana?secret=${SECRETO}`);
  assert.equal(r.emisor, 'Banco');
});

test('extrae la URI de un enlace #add= del Portal', () => {
  const uri = `otpauth://totp/Portal:ana?secret=${SECRETO}&issuer=Portal`;
  const enlace = `https://localhost:8443/app/#add=${encodeURIComponent(uri)}`;
  assert.equal(extraerDeEnlace(enlace), uri);
  assert.equal(extraerDeEnlace(uri), uri);
});

test('alta manual: valida y vuelve a construir la URI', () => {
  const datos = validarCuenta({ emisor: ' Portal ', cuenta: 'ana', secreto: 'gezd gnbv gy3t qojq gezd gnbv gy3t qojq', algoritmo: 'sha512', digitos: '6', periodo: '60' });
  assert.equal(datos.emisor, 'Portal');
  assert.equal(datos.secreto, SECRETO);
  assert.equal(datos.algoritmo, 'SHA512');
  assert.deepEqual(analizarOtpauth(construirOtpauth(datos)), datos);
});

test('formato Key URI estándar (D3): buildOtpauthUri cumple esquema otpauth://totp/issuer:cuenta y parámetros requeridos', async () => {
  const { buildOtpauthUri } = await import('../../backend/src/core/totp/totp.js');
  const perfiles = [
    { algoritmo: 'SHA256', digitos: 6, bytes: 32, periodo: 30 },
    { algoritmo: 'SHA512', digitos: 8, bytes: 64, periodo: 30 },
    { algoritmo: 'SHA1', digitos: 6, bytes: 20, periodo: 30 },
  ];
  for (const p of perfiles) {
    const semilla = Buffer.alloc(p.bytes, 0x35);
    const uri = buildOtpauthUri({
      semilla,
      emisor: 'Servicio Soberano',
      cuenta: 'ciudadano.01@ejemplo.local',
      algoritmo: p.algoritmo,
      digitos: p.digitos,
      periodo: p.periodo,
    });
    assert.ok(uri.startsWith('otpauth://totp/'), `Prefijo inválido: ${uri}`);
    const parsed = new URL(uri);
    const etiqueta = decodeURIComponent(parsed.pathname.replace(/^\/+/, ''));
    assert.equal(etiqueta, 'Servicio Soberano:ciudadano.01@ejemplo.local');
    assert.equal(parsed.searchParams.get('issuer'), 'Servicio Soberano');
    assert.equal(parsed.searchParams.get('algorithm'), p.algoritmo);
    assert.equal(parsed.searchParams.get('digits'), String(p.digitos));
    assert.equal(parsed.searchParams.get('period'), String(p.periodo));
    assert.match(parsed.searchParams.get('secret') || '', /^[A-Z2-7]{32,}$/);

    // Verificación de ida y vuelta en el analizador de la PWA
    const cuenta = analizarOtpauth(uri);
    assert.equal(cuenta.algoritmo, p.algoritmo);
    assert.equal(cuenta.digitos, p.digitos);
    assert.equal(cuenta.periodo, p.periodo);
  }
});
