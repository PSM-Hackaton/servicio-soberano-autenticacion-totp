// Pruebas de la cédula exportada por el SDK (la app integradora deriva el user_ref igual que el servicio).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';

import { normalizarCedula, derivarUserRefDesdeCedula } from '../src/index.js';

const SECRETO = Buffer.alloc(32, 9).toString('base64url');

test('normalizarCedula: válidas e inválidas', () => {
  assert.deepEqual(normalizarCedula('V-12.345.678'), { nacionalidad: 'V', numero: '12345678', canonica: 'V12345678', formateada: 'V-12.345.678' });
  assert.equal(normalizarCedula('E 80.000.003').canonica, 'E80000003');
  assert.equal(normalizarCedula('v12345678').formateada, 'V-12.345.678');
  for (const x of ['J-12345678', 'V-01234567', 'V12345', 'V1234567890', 'V-12.34.567', 'V12345678!', 'V 12 345 678']) {
    assert.equal(normalizarCedula(x), null, x);
  }
});

test('derivarUserRefDesdeCedula: prefijo + HMAC-SHA256 en base64url, apto como user_ref', () => {
  const ref = derivarUserRefDesdeCedula('V-12.345.678', SECRETO, 'ciud_');
  assert.equal(ref, `ciud_${createHmac('sha256', Buffer.alloc(32, 9)).update('V12345678').digest('base64url')}`);
  assert.match(ref, /^[A-Za-z0-9_-]{1,128}$/);
  assert.equal(derivarUserRefDesdeCedula('X-1', SECRETO), null);
  assert.throws(() => derivarUserRefDesdeCedula('V12345678', 'secreto-corto'), TypeError);
});
