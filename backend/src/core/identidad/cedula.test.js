// Pruebas de la normalización de la cédula venezolana y de la derivación del user_ref.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';

import { normalizarCedula, derivarUserRefDesdeCedula } from './cedula.js';
import * as sdk from '../../../../sdk/src/index.js';

const SECRETO = Buffer.alloc(32, 7).toString('base64url');

describe('normalizarCedula', () => {
  test('acepta las formas habituales y produce canónica y formateada', () => {
    const casos = [
      ['V-12.345.678', 'V', '12345678', 'V12345678', 'V-12.345.678'],
      ['v12345678', 'V', '12345678', 'V12345678', 'V-12.345.678'],
      ['E 80.000.003', 'E', '80000003', 'E80000003', 'E-80.000.003'],
      ['e-80000003', 'E', '80000003', 'E80000003', 'E-80.000.003'],
      ['V123456', 'V', '123456', 'V123456', 'V-123.456'],
      ['V-123.456', 'V', '123456', 'V123456', 'V-123.456'],
      ['V-123.456.789', 'V', '123456789', 'V123456789', 'V-123.456.789'],
      ['  V-1.234.567  ', 'V', '1234567', 'V1234567', 'V-1.234.567'],
      ['V 9999999', 'V', '9999999', 'V9999999', 'V-9.999.999'],
    ];
    for (const [entrada, nacionalidad, numero, canonica, formateada] of casos) {
      assert.deepEqual(normalizarCedula(entrada), { nacionalidad, numero, canonica, formateada }, entrada);
    }
  });

  test('rechaza nacionalidades, longitudes, ceros a la izquierda y caracteres ajenos', () => {
    const invalidos = [
      '', 'V', 'V-', '12345678', 'J-12345678', 'G12345678', 'P12345678', 'X-12.345.678',
      'V12345', 'V-1.234', 'V1234567890', 'V-1.234.567.890',
      'V01234567', 'V-012.345.678', 'V0',
      'V--12345678', 'V -12345678', 'V- 12345678', 'V_12345678', 'V.12345678', 'V-12,345,678',
      'V-12.34.5678', 'V-1234.567', 'V-12.345678', 'V-12 345 678', 'V12345678x', 'V12345678 9',
      'V١٢٣٤٥٦٧٨', 'Ｖ12345678', 'V12345678​', 'V\t12345678', 'V-12.345.678\n1',
      `V${'1'.repeat(40)}`,
      null, undefined, 12345678, {}, [],
    ];
    for (const x of invalidos) assert.equal(normalizarCedula(x), null, JSON.stringify(x));
  });
});

describe('derivarUserRefDesdeCedula', () => {
  test('prefijo + base64url(HMAC-SHA256(canónica, secreto)); misma salida para cualquier forma escrita', () => {
    const esperado = `ciud_${createHmac('sha256', Buffer.alloc(32, 7)).update('V12345678').digest('base64url')}`;
    assert.equal(derivarUserRefDesdeCedula('V-12.345.678', SECRETO, 'ciud_'), esperado);
    assert.equal(derivarUserRefDesdeCedula('v12345678', SECRETO, 'ciud_'), esperado);
    assert.equal(derivarUserRefDesdeCedula(' V 12345678 ', SECRETO, 'ciud_'), esperado);
    assert.equal(derivarUserRefDesdeCedula('V12345678', SECRETO).length, 43, 'sin prefijo: 43 caracteres');
    assert.notEqual(derivarUserRefDesdeCedula('E12345678', SECRETO), derivarUserRefDesdeCedula('V12345678', SECRETO));
    assert.notEqual(
      derivarUserRefDesdeCedula('V12345678', randomBytes(32).toString('base64url')),
      derivarUserRefDesdeCedula('V12345678', SECRETO),
    );
    assert.doesNotMatch(derivarUserRefDesdeCedula('V12345678', SECRETO, 'p:'), /12345678/);
  });

  test('cédula inválida → null; secreto o prefijo inválidos → TypeError', () => {
    assert.equal(derivarUserRefDesdeCedula('J-12345678', SECRETO), null);
    assert.throws(() => derivarUserRefDesdeCedula('V12345678', 'corto'), TypeError);
    assert.throws(() => derivarUserRefDesdeCedula('V12345678', SECRETO, 'con espacio'), TypeError);
    assert.throws(() => derivarUserRefDesdeCedula('V12345678', SECRETO, 'x'.repeat(33)), TypeError);
    assert.throws(() => derivarUserRefDesdeCedula('V12345678', 42), TypeError);
  });

  test('el SDK exporta una copia idéntica del módulo', () => {
    const backend = readFileSync(new URL('./cedula.js', import.meta.url), 'utf8');
    const copia = readFileSync(new URL('../../../../sdk/src/cedula.js', import.meta.url), 'utf8');
    assert.equal(copia, backend);
    assert.equal(sdk.derivarUserRefDesdeCedula('V-12.345.678', SECRETO, 'ciud_'), derivarUserRefDesdeCedula('V12345678', SECRETO, 'ciud_'));
    assert.deepEqual(sdk.normalizarCedula('E 80.000.003'), normalizarCedula('E80000003'));
  });
});
