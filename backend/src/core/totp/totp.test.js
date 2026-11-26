import { test } from 'node:test';
import assert from 'node:assert/strict';
import { base32Encode, base32Decode } from './base32.js';
import {
  generateHotp, generateTotp, verifyTotpWithDrift, resyncTwoConsecutiveCodes, buildOtpauthUri, pasoDeTiempo,
} from './totp.js';

const SEMILLAS = {
  SHA1: Buffer.from('12345678901234567890'),
  SHA256: Buffer.from('12345678901234567890123456789012'),
  SHA512: Buffer.from('1234567890123456789012345678901234567890123456789012345678901234'),
};

// RFC 6238, Apéndice B (8 dígitos, periodo 30 s)
const VECTORES_RFC6238 = [
  [59, '94287082', '46119246', '90693936'],
  [1111111109, '07081804', '68084774', '25091201'],
  [1111111111, '14050471', '67062674', '99943326'],
  [1234567890, '89005924', '91819424', '93441116'],
  [2000000000, '69279037', '90698825', '38618901'],
  [20000000000, '65353130', '77737706', '47863826'],
];

test('RFC 6238 Apéndice B: SHA-1, SHA-256 y SHA-512', () => {
  for (const [segundos, sha1, sha256, sha512] of VECTORES_RFC6238) {
    const esperado = { SHA1: sha1, SHA256: sha256, SHA512: sha512 };
    for (const algoritmo of ['SHA1', 'SHA256', 'SHA512']) {
      const codigo = generateTotp(SEMILLAS[algoritmo], segundos * 1000, { algoritmo, digitos: 8, periodo: 30 });
      assert.equal(codigo, esperado[algoritmo], `${algoritmo} en t=${segundos}`);
    }
  }
});

test('RFC 4226 Apéndice D: HOTP SHA-1, 6 dígitos', () => {
  const esperados = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
  esperados.forEach((codigo, contador) => assert.equal(generateHotp(SEMILLAS.SHA1, contador, 'SHA1', 6), codigo));
});

test('Base32 RFC 4648 (ida y vuelta)', () => {
  const vectores = { '': '', f: 'MY', fo: 'MZXQ', foo: 'MZXW6', foob: 'MZXW6YQ', fooba: 'MZXW6YTB', foobar: 'MZXW6YTBOI' };
  for (const [texto, b32] of Object.entries(vectores)) {
    assert.equal(base32Encode(Buffer.from(texto)), b32);
    assert.equal(base32Decode(b32).toString(), texto);
  }
  assert.throws(() => base32Decode('ABC1'));
});

const POLITICA = { algoritmo: 'SHA256', digitos: 6, periodo: 30, ventana: 1 };
const AHORA = 1_764_000_000_000;

test('verifica el código actual y los de la ventana ±1', () => {
  const semilla = SEMILLAS.SHA256;
  for (const desfase of [-1, 0, 1]) {
    const codigo = generateTotp(semilla, AHORA + desfase * 30_000, POLITICA);
    const r = verifyTotpWithDrift(semilla, codigo, AHORA, POLITICA);
    assert.equal(r.valid, true);
    assert.equal(r.driftSteps, desfase);
  }
  const fuera = generateTotp(semilla, AHORA + 2 * 30_000, POLITICA);
  assert.equal(verifyTotpWithDrift(semilla, fuera, AHORA, POLITICA).valid, false);
});

test('anti replay: un código aceptado no vuelve a valer', () => {
  const semilla = SEMILLAS.SHA256;
  const codigo = generateTotp(semilla, AHORA, POLITICA);
  const primero = verifyTotpWithDrift(semilla, codigo, AHORA, POLITICA);
  assert.equal(primero.valid, true);
  const segundo = verifyTotpWithDrift(semilla, codigo, AHORA + 5_000, { ...POLITICA, lastStep: primero.matchedStep });
  assert.deepEqual([segundo.valid, segundo.reason], [false, 'replay']);
});

test('la deriva guardada recentra la ventana', () => {
  const semilla = SEMILLAS.SHA512;
  const politica = { algoritmo: 'SHA512', digitos: 8, periodo: 30, ventana: 1 };
  const codigo = generateTotp(semilla, AHORA + 4 * 30_000, politica);
  assert.equal(verifyTotpWithDrift(semilla, codigo, AHORA, politica).valid, false);
  const r = verifyTotpWithDrift(semilla, codigo, AHORA, { ...politica, driftSteps: 4 });
  assert.deepEqual([r.valid, r.driftSteps], [true, 4]);
});

test('rechaza formatos inválidos sin lanzar error', () => {
  for (const codigo of ['', '12345', '1234567', 'abcdef', '12 456', null, 123456]) {
    const r = verifyTotpWithDrift(SEMILLAS.SHA256, codigo, AHORA, POLITICA);
    assert.deepEqual([r.valid, r.reason], [false, 'formato']);
  }
});

test('resincroniza con dos códigos consecutivos dentro de ±10 pasos', () => {
  const semilla = SEMILLAS.SHA256;
  const c1 = generateTotp(semilla, AHORA - 7 * 30_000, POLITICA);
  const c2 = generateTotp(semilla, AHORA - 6 * 30_000, POLITICA);
  const r = resyncTwoConsecutiveCodes(semilla, c1, c2, AHORA, POLITICA);
  assert.deepEqual([r.valid, r.driftSteps], [true, -6]);
  assert.equal(r.matchedStep, pasoDeTiempo(AHORA, 30) - 6);
  assert.equal(resyncTwoConsecutiveCodes(semilla, c2, c1, AHORA, POLITICA).valid, false);
});

test('rechaza políticas inválidas', () => {
  assert.throws(() => generateTotp(SEMILLAS.SHA1, AHORA, { algoritmo: 'MD5', digitos: 6, periodo: 30 }));
  assert.throws(() => generateTotp(SEMILLAS.SHA1, AHORA, { algoritmo: 'SHA1', digitos: 7, periodo: 30 }));
  assert.throws(() => generateTotp(SEMILLAS.SHA1, AHORA, { algoritmo: 'SHA1', digitos: 6, periodo: 5 }));
});

test('URI otpauth incluye algoritmo, dígitos y periodo', () => {
  const uri = buildOtpauthUri({ semilla: Buffer.from('foobar'), emisor: 'Institución', cuenta: 'u-123', algoritmo: 'SHA512', digitos: 8, periodo: 30 });
  assert.match(uri, /^otpauth:\/\/totp\/Instituci%C3%B3n:u-123\?/);
  const params = new URL(uri).searchParams;
  assert.deepEqual(
    [params.get('secret'), params.get('algorithm'), params.get('digits'), params.get('period')],
    ['MZXW6YTBOI', 'SHA512', '8', '30'],
  );
});
