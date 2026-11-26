import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { generateSeed, crearVault, llavesDesdeEntorno, hashPepper, pepperDiario } from './vault.js';

const LLAVE_V1 = randomBytes(32);
const LLAVE_V2 = randomBytes(32);
const ERROR = { message: 'No se pudo descifrar' };

test('generateSeed respeta la longitud por algoritmo y rechaza algoritmos inválidos', () => {
  assert.equal(generateSeed('SHA1').length, 20);
  assert.equal(generateSeed('SHA256').length, 32);
  assert.equal(generateSeed('SHA512').length, 64);
  assert.notDeepEqual(generateSeed('SHA256'), generateSeed('SHA256'));
  assert.throws(() => generateSeed('MD5'));
  assert.throws(() => generateSeed('toString'));
});

test('crearVault valida longitud de llaves y versión activa', () => {
  assert.throws(() => crearVault({ llaves: { v1: randomBytes(16) }, versionActiva: 'v1' }));
  assert.throws(() => crearVault({ llaves: { v1: LLAVE_V1 }, versionActiva: 'v2' }));
});

test('cifrado y descifrado de semilla (ida y vuelta)', () => {
  const vault = crearVault({ llaves: { v1: LLAVE_V1 }, versionActiva: 'v1' });
  const semilla = generateSeed('SHA256');
  const registro = vault.encryptSeed(semilla, 'enr-1');
  assert.equal(registro.nonce.length, 12);
  assert.equal(registro.authTag.length, 16);
  assert.equal(registro.keyVersion, 'v1');
  assert.notDeepEqual(registro.ct, semilla);
  assert.deepEqual(vault.decryptSeed(registro, 'enr-1'), semilla);
  // Nonce aleatorio: dos cifrados de lo mismo difieren
  assert.notDeepEqual(vault.encryptSeed(semilla, 'enr-1').nonce, registro.nonce);
});

test('AAD distinta (otro enrollmentId) falla', () => {
  const vault = crearVault({ llaves: { v1: LLAVE_V1 }, versionActiva: 'v1' });
  const registro = vault.encryptSeed(generateSeed('SHA1'), 'enr-1');
  assert.throws(() => vault.decryptSeed(registro, 'enr-2'), ERROR);
});

test('tag o texto cifrado alterado falla', () => {
  const vault = crearVault({ llaves: { v1: LLAVE_V1 }, versionActiva: 'v1' });
  const registro = vault.encryptSeed(generateSeed('SHA1'), 'enr-1');
  const tag = Buffer.from(registro.authTag);
  tag[0] ^= 0x01;
  assert.throws(() => vault.decryptSeed({ ...registro, authTag: tag }, 'enr-1'), ERROR);
  const ct = Buffer.from(registro.ct);
  ct[0] ^= 0x01;
  assert.throws(() => vault.decryptSeed({ ...registro, ct }, 'enr-1'), ERROR);
});

test('versión de llave desconocida falla', () => {
  const vault = crearVault({ llaves: { v1: LLAVE_V1 }, versionActiva: 'v1' });
  const registro = vault.encryptSeed(generateSeed('SHA1'), 'enr-1');
  assert.throws(() => vault.decryptSeed({ ...registro, keyVersion: 'v9' }, 'enr-1'), ERROR);
  // Cambiar la versión también altera la AAD
  const otro = crearVault({ llaves: { v1: LLAVE_V1, v2: LLAVE_V1 }, versionActiva: 'v1' });
  assert.throws(() => otro.decryptSeed({ ...registro, keyVersion: 'v2' }, 'enr-1'), ERROR);
});

test('reencrypt pasa a la versión activa y sigue descifrando', () => {
  const antiguo = crearVault({ llaves: { v1: LLAVE_V1 }, versionActiva: 'v1' });
  const semilla = generateSeed('SHA512');
  const registro = antiguo.encryptSeed(semilla, 'enr-1');
  const nuevo = crearVault({ llaves: { v1: LLAVE_V1, v2: LLAVE_V2 }, versionActiva: 'v2' });
  const rotado = nuevo.reencrypt(registro, 'enr-1');
  assert.equal(rotado.keyVersion, 'v2');
  assert.deepEqual(nuevo.decryptSeed(rotado, 'enr-1'), semilla);
  assert.throws(() => antiguo.decryptSeed(rotado, 'enr-1'), ERROR);
});

test('encryptBlob / decryptBlob genéricos con contexto', () => {
  const vault = crearVault({ llaves: { v1: LLAVE_V1 }, versionActiva: 'v1' });
  const privada = Buffer.from('-----BEGIN PRIVATE KEY-----...');
  const registro = vault.encryptBlob(privada, 'firma:ed25519');
  assert.deepEqual(vault.decryptBlob(registro, 'firma:ed25519'), privada);
  assert.throws(() => vault.decryptBlob(registro, 'firma:otra'), ERROR);
});

test('llavesDesdeEntorno: configuración válida', () => {
  const env = {
    MASTER_KEY_VERSION: 'v2',
    MASTER_KEY_V1_HEX: LLAVE_V1.toString('hex'),
    MASTER_KEY_V2_HEX: LLAVE_V2.toString('hex').toUpperCase(),
    OTRA: 'x',
  };
  const { llaves, versionActiva } = llavesDesdeEntorno(env);
  assert.equal(versionActiva, 'v2');
  assert.deepEqual(Object.keys(llaves).sort(), ['v1', 'v2']);
  assert.deepEqual(llaves.v1, LLAVE_V1);
  assert.deepEqual(llaves.v2, LLAVE_V2);
  const vault = crearVault({ llaves, versionActiva });
  assert.equal(vault.encryptSeed(generateSeed('SHA1'), 'e').keyVersion, 'v2');
});

test('llavesDesdeEntorno: configuración inválida', () => {
  assert.throws(() => llavesDesdeEntorno({}));
  assert.throws(() => llavesDesdeEntorno({ MASTER_KEY_VERSION: 'v1' }));
  assert.throws(() => llavesDesdeEntorno({ MASTER_KEY_VERSION: 'v1', MASTER_KEY_V1_HEX: 'abcd' }));
  assert.throws(() => llavesDesdeEntorno({ MASTER_KEY_VERSION: 'v1', MASTER_KEY_V1_HEX: 'z'.repeat(64) }));
  assert.throws(() => llavesDesdeEntorno({ MASTER_KEY_VERSION: 'v1', MASTER_KEY_V2_HEX: LLAVE_V2.toString('hex') }));
});

test('hashPepper es determinista y depende de la pimienta', () => {
  const a = hashPepper('192.0.2.1', 'pimienta');
  assert.equal(a, hashPepper('192.0.2.1', 'pimienta'));
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.notEqual(a, hashPepper('192.0.2.1', 'otra'));
  assert.notEqual(a, hashPepper('192.0.2.2', 'pimienta'));
});

test('pepperDiario cambia entre días y es estable dentro del día UTC', () => {
  const semilla = randomBytes(32);
  const d1 = pepperDiario(semilla, new Date('2026-11-26T00:00:01Z'));
  const d1b = pepperDiario(semilla, new Date('2026-11-26T23:59:59Z'));
  const d2 = pepperDiario(semilla, new Date('2026-11-27T00:00:00Z'));
  assert.equal(d1.length, 32);
  assert.deepEqual(d1, d1b);
  assert.notDeepEqual(d1, d2);
  assert.notEqual(hashPepper('192.0.2.1', d1), hashPepper('192.0.2.1', d2));
});
