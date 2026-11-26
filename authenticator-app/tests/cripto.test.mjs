// Pruebas del cifrado de la bóveda y de los respaldos (js/cripto.js) y de la política de PIN.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ITERACIONES_MINIMAS, ITERACIONES_PBKDF2, bytesAleatorios, cifrarJson, cifrarRespaldo, derivarLlave,
  descifrarJson, descifrarRespaldo,
} from '../js/cripto.js';
import { esperaParaFallos, problemaDePin } from '../js/boveda.js';

test('PBKDF2 usa al menos 310 000 iteraciones', () => {
  assert.ok(ITERACIONES_PBKDF2 >= 310_000);
});

test('AES-GCM: ida y vuelta, PIN incorrecto y AAD distinto fallan', async () => {
  const sal = bytesAleatorios(16);
  const llave = await derivarLlave('482915', sal, 1000);
  assert.equal(llave.extractable, false);
  const sobre = await cifrarJson(llave, { cuentas: [{ secreto: 'ABC' }] }, 'aad-1');
  assert.equal(sobre.iv.length, 12);
  assert.ok(!new TextDecoder().decode(sobre.datos).includes('ABC'));
  assert.deepEqual(await descifrarJson(llave, sobre, 'aad-1'), { cuentas: [{ secreto: 'ABC' }] });
  const otra = await derivarLlave('482916', sal, 1000);
  await assert.rejects(descifrarJson(otra, sobre, 'aad-1'));
  await assert.rejects(descifrarJson(llave, sobre, 'aad-2'));
  const alterado = { iv: sobre.iv, datos: sobre.datos.slice() };
  alterado.datos[0] ^= 1;
  await assert.rejects(descifrarJson(llave, alterado, 'aad-1'));
});

test('cada cifrado usa un nonce distinto', async () => {
  const llave = await derivarLlave('482915', bytesAleatorios(16), 1000);
  const a = await cifrarJson(llave, {}, 'x');
  const b = await cifrarJson(llave, {}, 'x');
  assert.notDeepEqual(a.iv, b.iv);
});

test('respaldo cifrado con contraseña', async () => {
  const datos = { version: 1, cuentas: [{ emisor: 'Portal', secreto: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' }] };
  const sobre = await cifrarRespaldo(datos, 'contraseña larga', ITERACIONES_MINIMAS);
  assert.equal(sobre.formato, 'autenticador-soberano-respaldo');
  assert.ok(!JSON.stringify(sobre).includes('GEZDGNBV'));
  assert.deepEqual(await descifrarRespaldo(sobre, 'contraseña larga'), datos);
  await assert.rejects(descifrarRespaldo(sobre, 'otra contraseña'), /incorrecta/);
  await assert.rejects(descifrarRespaldo({ ...sobre, kdf: { ...sobre.kdf, iteraciones: 1 } }, 'x'), /no admitidos/);
  await assert.rejects(descifrarRespaldo({ formato: 'otro' }, 'x'), /no es un respaldo/);
});

test('política de PIN', () => {
  assert.equal(problemaDePin('482915'), null);
  assert.match(problemaDePin('12345'), /al menos 6/);
  assert.match(problemaDePin('123456'), /secuencias/);
  assert.match(problemaDePin('987654'), /secuencias/);
  assert.match(problemaDePin('000000'), /repetir/);
  assert.match(problemaDePin('12a456'), /números/);
  assert.match(problemaDePin('1234567890123'), /máximo/);
});

test('espera progresiva tras fallos de PIN: 30 s, 2 min, 10 min, 1 h', () => {
  assert.deepEqual([1, 2, 3, 4].map(esperaParaFallos), [0, 0, 0, 0]);
  assert.deepEqual([5, 6, 7, 8, 20].map(esperaParaFallos), [30_000, 120_000, 600_000, 3_600_000, 3_600_000]);
});
