import test from 'node:test';
import assert from 'node:assert/strict';
import {
  decodeBase32,
  encodeBase32,
  generateTotp,
  parseOtpAuthUri,
  encryptVaultData,
  decryptVaultData,
} from './totp-core.js';

// Vectores oficiales del Apéndice B del RFC 6238 (semillas ASCII estándar)
const SEED_SHA1 = new TextEncoder().encode('12345678901234567890');
const SEED_SHA256 = new TextEncoder().encode('12345678901234567890123456789012');
const SEED_SHA512 = new TextEncoder().encode('1234567890123456789012345678901234567890123456789012345678901234');

test('RFC 6238 Apéndice B: SHA-1, SHA-256 y SHA-512 (8 dígitos) en Web Crypto', async () => {
  const vectors = [
    { ts: 59, sha1: '94287082', sha256: '46119246', sha512: '90693936' },
    { ts: 1111111109, sha1: '07081804', sha256: '68084774', sha512: '25091201' },
    { ts: 1111111111, sha1: '14050471', sha256: '67062674', sha512: '99943326' },
    { ts: 1234567890, sha1: '89005924', sha256: '91819424', sha512: '93441116' },
    { ts: 2000000000, sha1: '69279037', sha256: '90698825', sha512: '38618901' },
    { ts: 20000000000, sha1: '65353130', sha256: '77737706', sha512: '47863826' },
  ];

  for (const v of vectors) {
    const r1 = await generateTotp(SEED_SHA1, { algorithm: 'SHA1', digits: 8, period: 30, timestampMs: v.ts * 1000 });
    const r256 = await generateTotp(SEED_SHA256, { algorithm: 'SHA256', digits: 8, period: 30, timestampMs: v.ts * 1000 });
    const r512 = await generateTotp(SEED_SHA512, { algorithm: 'SHA512', digits: 8, period: 30, timestampMs: v.ts * 1000 });
    assert.equal(r1.code, v.sha1, `SHA1 fallo en t=${v.ts}`);
    assert.equal(r256.code, v.sha256, `SHA256 fallo en t=${v.ts}`);
    assert.equal(r512.code, v.sha512, `SHA512 fallo en t=${v.ts}`);
  }
});

test('Base32 encode/decode ida y vuelta y parser otpauth://', () => {
  const original = new Uint8Array([1, 2, 3, 4, 250, 251, 252, 253]);
  const b32 = encodeBase32(original);
  assert.deepEqual(decodeBase32(b32), original);

  const uri = 'otpauth://totp/MincytSoberanoTOTP:ciudadano-demo?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=MincytSoberanoTOTP&algorithm=SHA256&digits=6&period=30';
  const parsed = parseOtpAuthUri(uri);
  assert.equal(parsed.issuer, 'MincytSoberanoTOTP');
  assert.equal(parsed.account, 'ciudadano-demo');
  assert.equal(parsed.algorithm, 'SHA256');
  assert.equal(parsed.digits, 6);
  assert.equal(parsed.period, 30);
});

test('Bóveda cifrada con PIN (PBKDF2-SHA256 + AES-256-GCM) falla con PIN incorrecto', async () => {
  const payload = { accounts: [{ id: '1', issuer: 'Test', secret: 'JBSWY3DPEHPK3PXP' }] };
  const envelope = await encryptVaultData(payload, '246810', { iterations: 10_000 });
  assert.ok(envelope.ciphertext && envelope.iv && envelope.salt);

  const decrypted = await decryptVaultData(envelope, '246810');
  assert.deepEqual(decrypted, payload);

  await assert.rejects(() => decryptVaultData(envelope, '999999'));
});
