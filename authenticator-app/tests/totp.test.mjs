// Pruebas del motor TOTP del navegador (js/totp.js) en Node 22, con Web Crypto nativo.
// Ejecutar desde la raíz del repo: node --test authenticator-app/tests/*.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  agruparCodigo, base32Decode, base32Encode, generarHotp, generarTotp, importarSemilla,
  pasoDeTiempo, segundosRestantes,
} from '../js/totp.js';

const texto = (s) => new TextEncoder().encode(s);
const SEMILLAS = {
  SHA1: texto('12345678901234567890'),
  SHA256: texto('12345678901234567890123456789012'),
  SHA512: texto('1234567890123456789012345678901234567890123456789012345678901234'),
};

// RFC 6238, Apéndice B (8 dígitos, periodo 30 s, T0 = 0).
const VECTORES = [
  [59, '94287082', '46119246', '90693936'],
  [1111111109, '07081804', '68084774', '25091201'],
  [1111111111, '14050471', '67062674', '99943326'],
  [1234567890, '89005924', '91819424', '93441116'],
  [2000000000, '69279037', '90698825', '38618901'],
  [20000000000, '65353130', '77737706', '47863826'],
];

for (const [segundos, sha1, sha256, sha512] of VECTORES) {
  test(`RFC 6238 Apéndice B, T = ${segundos} s`, async () => {
    const politica = { digitos: 8, periodo: 30 };
    assert.equal(await generarTotp(SEMILLAS.SHA1, segundos * 1000, { ...politica, algoritmo: 'SHA1' }), sha1);
    assert.equal(await generarTotp(SEMILLAS.SHA256, segundos * 1000, { ...politica, algoritmo: 'SHA256' }), sha256);
    assert.equal(await generarTotp(SEMILLAS.SHA512, segundos * 1000, { ...politica, algoritmo: 'SHA512' }), sha512);
  });
}

test('RFC 4226 Apéndice D: HOTP de 6 dígitos para los contadores 0 a 9', async () => {
  const esperados = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
  const llave = await importarSemilla(SEMILLAS.SHA1, 'SHA1');
  for (let i = 0; i < esperados.length; i++) {
    assert.equal(await generarHotp(llave, i, 'SHA1', 6), esperados[i]);
  }
});

test('una llave CryptoKey no extraíble da el mismo código que los bytes', async () => {
  const llave = await importarSemilla(SEMILLAS.SHA256, 'SHA256');
  assert.equal(llave.extractable, false);
  const p = { algoritmo: 'SHA256', digitos: 6, periodo: 30 };
  assert.equal(await generarTotp(llave, 1_700_000_000_000, p), await generarTotp(SEMILLAS.SHA256, 1_700_000_000_000, p));
});

test('Base32 RFC 4648: vectores y ida y vuelta', () => {
  const casos = [['', ''], ['f', 'MY'], ['fo', 'MZXQ'], ['foo', 'MZXW6'], ['foob', 'MZXW6YQ'], ['fooba', 'MZXW6YTB'], ['foobar', 'MZXW6YTBOI']];
  for (const [claro, codificado] of casos) {
    assert.equal(base32Encode(texto(claro)), codificado);
    assert.deepEqual(base32Decode(codificado), texto(claro));
  }
  assert.deepEqual(base32Decode('mzxw 6ytb-oi======'), texto('foobar'));
  assert.throws(() => base32Decode('MZXW1'), /Base32/);
  const azar = crypto.getRandomValues(new Uint8Array(64));
  assert.deepEqual(base32Decode(base32Encode(azar)), azar);
});

test('política: rechaza algoritmos, dígitos y periodos fuera de rango', async () => {
  const s = SEMILLAS.SHA1;
  await assert.rejects(generarTotp(s, 0, { algoritmo: 'MD5', digitos: 6, periodo: 30 }), /Algoritmo/);
  await assert.rejects(generarTotp(s, 0, { algoritmo: 'SHA1', digitos: 7, periodo: 30 }), /Dígitos/);
  await assert.rejects(generarTotp(s, 0, { algoritmo: 'SHA1', digitos: 6, periodo: 10 }), /Periodo/);
  await assert.rejects(generarTotp(s, 0, { algoritmo: 'SHA1', digitos: 6, periodo: 61 }), /Periodo/);
  await assert.rejects(generarTotp(s, 0, { algoritmo: 'constructor', digitos: 6, periodo: 30 }), /Algoritmo/);
});

test('utilidades de tiempo y formato', () => {
  assert.equal(pasoDeTiempo(59_000, 30), 1);
  assert.equal(segundosRestantes(60_000, 30), 30);
  assert.equal(segundosRestantes(85_500, 30), 4.5);
  assert.equal(agruparCodigo('123456'), '123 456');
  assert.equal(agruparCodigo('12345678'), '1234 5678');
});

test('coincide con el motor del backend (backend/src/core/totp) en 300 casos aleatorios', async (t) => {
  let backend;
  try {
    backend = await import('../../backend/src/core/totp/totp.js');
  } catch {
    t.skip('backend no disponible en esta copia');
    return;
  }
  const largos = { SHA1: 20, SHA256: 32, SHA512: 64 };
  for (let i = 0; i < 300; i++) {
    const algoritmo = ['SHA1', 'SHA256', 'SHA512'][i % 3];
    const digitos = i % 2 ? 8 : 6;
    const periodo = [15, 30, 45, 60][i % 4];
    const semilla = crypto.getRandomValues(new Uint8Array(largos[algoritmo]));
    const instante = Math.floor(Math.random() * 4_000_000_000_000);
    const politica = { algoritmo, digitos, periodo };
    assert.equal(
      await generarTotp(semilla, instante, politica),
      backend.generateTotp(Buffer.from(semilla), instante, politica),
      `${algoritmo}/${digitos}/${periodo} en ${instante}`,
    );
  }
});
