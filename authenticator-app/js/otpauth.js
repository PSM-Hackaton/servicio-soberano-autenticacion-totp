// Validación estricta de URIs otpauth://totp/ y de cuentas dadas de alta a mano.
// Módulo puro (sin DOM): se prueba en Node.

import { ALGORITMOS, PERIODO_MAX, PERIODO_MIN, base32Decode, base32Encode, normalizarBase32 } from './totp.js';

export const LIMITES = Object.freeze({
  uriMax: 2048,
  textoMax: 100,
  // RFC 4226 §4 R6: la semilla debe tener al menos 128 bits.
  semillaMinBytes: 16,
  semillaMaxBytes: 128,
});

export class ErrorCuenta extends Error {
  constructor(mensaje) {
    super(mensaje);
    this.name = 'ErrorCuenta';
  }
}

// Caracteres de control y de reordenamiento bidireccional (evitan suplantar emisores visualmente).
const INVISIBLES = /[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁠-⁩﻿]/g;

/** Limpia y acota un texto visible (emisor o cuenta). */
export function limpiarTexto(valor, campo) {
  const limpio = String(valor ?? '').replace(INVISIBLES, '').replace(/\s+/g, ' ').trim();
  if (limpio.length > LIMITES.textoMax) throw new ErrorCuenta(`El ${campo} supera ${LIMITES.textoMax} caracteres.`);
  return limpio;
}

/**
 * Valida y normaliza los datos de una cuenta. Lanza ErrorCuenta con un mensaje claro.
 * @param {{ emisor?: string, cuenta?: string, secreto: string, algoritmo?: string, digitos?: number|string, periodo?: number|string }} datos
 * @returns {{ emisor: string, cuenta: string, secreto: string, algoritmo: 'SHA1'|'SHA256'|'SHA512', digitos: 6|8, periodo: number }}
 */
export function validarCuenta(datos) {
  const emisor = limpiarTexto(datos.emisor, 'emisor');
  const cuenta = limpiarTexto(datos.cuenta, 'nombre de la cuenta');
  if (!emisor && !cuenta) throw new ErrorCuenta('Indica al menos el emisor o el nombre de la cuenta.');

  const algoritmo = String(datos.algoritmo ?? 'SHA1').toUpperCase();
  if (!Object.hasOwn(ALGORITMOS, algoritmo)) throw new ErrorCuenta('Algoritmo no permitido. Usa SHA1, SHA256 o SHA512.');

  const textoDigitos = String(datos.digitos ?? '6');
  if (textoDigitos !== '6' && textoDigitos !== '8') throw new ErrorCuenta('El código debe tener 6 u 8 dígitos.');

  const textoPeriodo = String(datos.periodo ?? '30');
  if (!/^\d{1,3}$/.test(textoPeriodo)) throw new ErrorCuenta('El periodo debe ser un número entero de segundos.');
  const periodo = Number(textoPeriodo);
  if (periodo < PERIODO_MIN || periodo > PERIODO_MAX) {
    throw new ErrorCuenta(`El periodo debe estar entre ${PERIODO_MIN} y ${PERIODO_MAX} segundos.`);
  }

  const crudo = normalizarBase32(datos.secreto ?? '');
  if (!crudo) throw new ErrorCuenta('Falta la clave secreta.');
  if (!/^[A-Z2-7]+$/.test(crudo)) throw new ErrorCuenta('La clave solo puede tener letras A–Z y números 2–7.');
  const bytes = base32Decode(crudo);
  if (bytes.length < LIMITES.semillaMinBytes) {
    throw new ErrorCuenta('La clave es demasiado corta: debe tener al menos 128 bits (26 caracteres).');
  }
  if (bytes.length > LIMITES.semillaMaxBytes) throw new ErrorCuenta('La clave es demasiado larga.');

  return { emisor, cuenta, secreto: base32Encode(bytes), algoritmo, digitos: Number(textoDigitos), periodo };
}

function decodificar(texto, campo) {
  try {
    return decodeURIComponent(texto);
  } catch {
    throw new ErrorCuenta(`La ${campo} de la URI está mal codificada.`);
  }
}

/**
 * Analiza una URI otpauth://totp/Emisor:cuenta?secret=…&issuer=…&algorithm=…&digits=…&period=…
 * Rechaza HOTP, parámetros repetidos, emisores contradictorios y valores fuera de rango.
 * @param {string} uri
 */
export function analizarOtpauth(uri) {
  const texto = String(uri ?? '').trim();
  if (!texto) throw new ErrorCuenta('Pega la URI que empieza por otpauth://totp/.');
  if (texto.length > LIMITES.uriMax) throw new ErrorCuenta('La URI es demasiado larga.');
  if (/^otpauth:\/\/hotp\//i.test(texto)) throw new ErrorCuenta('Las cuentas HOTP (por contador) no están permitidas; solo TOTP.');
  if (!/^otpauth:\/\/totp\//i.test(texto)) throw new ErrorCuenta('La URI debe empezar por otpauth://totp/.');

  const resto = texto.slice('otpauth://totp/'.length);
  const corte = resto.indexOf('?');
  if (corte === -1) throw new ErrorCuenta('A la URI le faltan los parámetros (secret=…).');
  if (resto.includes('#')) throw new ErrorCuenta('La URI contiene caracteres no permitidos.');

  const etiqueta = decodificar(resto.slice(0, corte), 'etiqueta');
  const parametros = new URLSearchParams(resto.slice(corte + 1));

  for (const clave of ['secret', 'issuer', 'algorithm', 'digits', 'period']) {
    if (parametros.getAll(clave).length > 1) throw new ErrorCuenta(`El parámetro «${clave}» aparece repetido.`);
  }
  if (parametros.has('counter')) throw new ErrorCuenta('Las cuentas HOTP (por contador) no están permitidas; solo TOTP.');

  let emisorEtiqueta = '';
  let cuenta = etiqueta;
  const dosPuntos = etiqueta.indexOf(':');
  if (dosPuntos !== -1) {
    emisorEtiqueta = etiqueta.slice(0, dosPuntos);
    cuenta = etiqueta.slice(dosPuntos + 1);
  }
  const emisorParametro = parametros.get('issuer');
  const a = limpiarTexto(emisorEtiqueta, 'emisor');
  const b = limpiarTexto(emisorParametro ?? '', 'emisor');
  if (a && b && a !== b) {
    throw new ErrorCuenta(`El emisor de la etiqueta («${a}») no coincide con el del parámetro issuer («${b}»).`);
  }

  return validarCuenta({
    emisor: b || a,
    cuenta,
    secreto: parametros.get('secret') ?? '',
    algoritmo: parametros.get('algorithm') ?? 'SHA1',
    digitos: parametros.get('digits') ?? '6',
    periodo: parametros.get('period') ?? '30',
  });
}

/**
 * Extrae una URI otpauth de un enlace del Portal (…/app/#add=<uri codificada>) o la devuelve tal cual.
 * @param {string} texto
 */
export function extraerDeEnlace(texto) {
  const t = String(texto ?? '').trim();
  const i = t.indexOf('#add=');
  if (i === -1) return t;
  return decodificar(t.slice(i + 5), 'dirección del enlace');
}

/** Construye la URI otpauth de una cuenta (para respaldos y pruebas). */
export function construirOtpauth({ emisor, cuenta, secreto, algoritmo, digitos, periodo }) {
  const etiqueta = emisor ? `${encodeURIComponent(emisor)}:${encodeURIComponent(cuenta)}` : encodeURIComponent(cuenta);
  const p = new URLSearchParams({ secret: secreto, algorithm: algoritmo, digits: String(digitos), period: String(periodo) });
  if (emisor) p.set('issuer', emisor);
  return `otpauth://totp/${etiqueta}?${p}`;
}
