// Motor TOTP RFC 6238 / RFC 4226 + Base32 + parser otpauth:// + cifrado de bóveda PBKDF2/AES-256-GCM.
// Funciona 100% con Web Crypto API (navegador y Node.js 22). Cero dependencias externas.

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const ALGO_MAP = Object.freeze({
  SHA1: 'SHA-1',
  'SHA-1': 'SHA-1',
  SHA256: 'SHA-256',
  'SHA-256': 'SHA-256',
  SHA512: 'SHA-512',
  'SHA-512': 'SHA-512',
});

/**
 * Decodifica una cadena Base32 (RFC 4648) ignorando espacios, guiones y relleno '='.
 * @param {string} input
 * @returns {Uint8Array}
 */
export function decodeBase32(input) {
  if (typeof input !== 'string') throw new Error('Secreto Base32 inválido');
  const cleaned = input.toUpperCase().replace(/[\s-]+/g, '').replace(/=+$/g, '');
  if (!cleaned.length) throw new Error('Secreto Base32 vacío');

  let bits = 0;
  let value = 0;
  /** @type {number[]} */
  const out = [];

  for (let i = 0; i < cleaned.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(cleaned[i]);
    if (idx === -1) throw new Error(`Carácter Base32 inválido: ${cleaned[i]}`);
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  if (out.length === 0) throw new Error('Secreto Base32 insuficiente');
  return new Uint8Array(out);
}

/**
 * Codifica bytes a Base32 sin relleno (útil para mostrar clave manual).
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function encodeBase32(bytes) {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

/**
 * Normaliza el nombre del algoritmo al formato Web Crypto ('SHA-256', 'SHA-512', 'SHA-1').
 * @param {string} [algorithm]
 * @returns {'SHA-256' | 'SHA-512' | 'SHA-1'}
 */
export function normalizeAlgorithm(algorithm = 'SHA256') {
  const key = String(algorithm).toUpperCase().trim();
  const mapped = ALGO_MAP[key];
  if (!mapped) throw new Error(`Algoritmo no soportado: ${algorithm}`);
  return /** @type {'SHA-256' | 'SHA-512' | 'SHA-1'} */ (mapped);
}

/**
 * Calcula HOTP (RFC 4226) usando Web Crypto SubtleCrypto.
 * @param {Uint8Array} secretBytes
 * @param {number | bigint} counter
 * @param {{ algorithm?: string, digits?: number }} [options]
 * @returns {Promise<string>}
 */
export async function generateHotp(secretBytes, counter, { algorithm = 'SHA256', digits = 6 } = {}) {
  if (!(secretBytes instanceof Uint8Array) || secretBytes.length === 0) {
    throw new Error('La semilla debe ser Uint8Array no vacío');
  }
  if (digits !== 6 && digits !== 8) {
    throw new Error('Los dígitos soportados son 6 u 8');
  }
  const hashName = normalizeAlgorithm(algorithm);

  // Contador big-endian de 8 bytes (RFC 4226 §5.3)
  const msg = new Uint8Array(8);
  const view = new DataView(msg.buffer);
  view.setBigUint64(0, BigInt(counter), false);

  const subtle = globalThis.crypto.subtle;
  const key = await subtle.importKey(
    'raw',
    secretBytes,
    { name: 'HMAC', hash: { name: hashName } },
    false,
    ['sign'],
  );
  const sig = new Uint8Array(await subtle.sign('HMAC', key, msg));

  // Truncado dinámico RFC 4226 §5.4
  const offset = sig[sig.length - 1] & 0x0f;
  const binary =
    ((sig[offset] & 0x7f) << 24)
    | ((sig[offset + 1] & 0xff) << 16)
    | ((sig[offset + 2] & 0xff) << 8)
    | (sig[offset + 3] & 0xff);

  const mod = 10 ** digits;
  return String(binary % mod).padStart(digits, '0');
}

/**
 * Calcula TOTP (RFC 6238) a partir de bytes o secreto Base32.
 * @param {Uint8Array | string} secret
 * @param {{ algorithm?: string, digits?: number, period?: number, timestampMs?: number }} [options]
 * @returns {Promise<{ code: string, step: number, remainingSeconds: number, period: number }>}
 */
export async function generateTotp(secret, {
  algorithm = 'SHA256',
  digits = 6,
  period = 30,
  timestampMs = Date.now(),
} = {}) {
  if (!Number.isInteger(period) || period < 15 || period > 60) {
    throw new Error('El período debe estar entre 15 y 60 segundos');
  }
  const bytes = typeof secret === 'string' ? decodeBase32(secret) : secret;
  const epochSeconds = Math.floor(timestampMs / 1000);
  const step = Math.floor(epochSeconds / period);
  const remainingSeconds = period - (epochSeconds % period);
  const code = await generateHotp(bytes, step, { algorithm, digits });
  return { code, step, remainingSeconds, period };
}

/**
 * Parsea una URI estándar `otpauth://totp/Issuer:account?secret=...&issuer=...&algorithm=SHA256&digits=6&period=30`.
 * @param {string} uri
 */
export function parseOtpAuthUri(uri) {
  if (typeof uri !== 'string' || !uri.trim().toLowerCase().startsWith('otpauth://totp/')) {
    throw new Error('URI inválida: debe iniciar con otpauth://totp/');
  }
  const parsed = new URL(uri.trim());
  const rawLabel = decodeURIComponent(parsed.pathname.replace(/^\/+/, ''));
  let issuer = parsed.searchParams.get('issuer') || '';
  let account = rawLabel;
  if (rawLabel.includes(':')) {
    const [labelIssuer, ...rest] = rawLabel.split(':');
    if (!issuer) issuer = labelIssuer.trim();
    account = rest.join(':').trim();
  }
  const secret = (parsed.searchParams.get('secret') || '').toUpperCase().replace(/[\s-]+/g, '');
  // Valida Base32
  decodeBase32(secret);

  const rawAlg = (parsed.searchParams.get('algorithm') || 'SHA256').toUpperCase().replace('-', '');
  if (!['SHA256', 'SHA512', 'SHA1'].includes(rawAlg)) {
    throw new Error(`Algoritmo no soportado en URI: ${rawAlg}`);
  }
  const digits = Number(parsed.searchParams.get('digits') || '6');
  if (digits !== 6 && digits !== 8) throw new Error('Dígitos inválidos en URI (solo 6 u 8)');
  const period = Number(parsed.searchParams.get('period') || '30');
  if (!Number.isInteger(period) || period < 15 || period > 60) {
    throw new Error('Período inválido en URI (15–60 s)');
  }

  return {
    issuer: issuer || 'Institución Soberana',
    account: account || 'usuario',
    secret,
    algorithm: /** @type {'SHA256' | 'SHA512' | 'SHA1'} */ (rawAlg),
    digits: /** @type {6 | 8} */ (digits),
    period,
  };
}

// ---------- Cifrado de bóveda con PIN (PBKDF2-SHA256 + AES-256-GCM) ----------

const PBKDF2_ITERATIONS = 150_000;

/** @param {Uint8Array} bytes */
function toBase64(bytes) {
  if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64');
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** @param {string} b64 */
function fromBase64(b64) {
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(b64, 'base64'));
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Deriva una clave AES-256-GCM a partir del PIN y la sal.
 * @param {string} pin
 * @param {Uint8Array} salt
 * @param {number} [iterations]
 */
export async function derivePinKey(pin, salt, iterations = PBKDF2_ITERATIONS) {
  if (typeof pin !== 'string' || pin.length < 4 || pin.length > 32) {
    throw new Error('El PIN debe tener entre 4 y 32 caracteres');
  }
  const subtle = globalThis.crypto.subtle;
  const baseKey = await subtle.importKey(
    'raw',
    new TextEncoder().encode(pin),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Cifra un objeto JSON de cuentas de la bóveda con AES-256-GCM usando llave derivada del PIN.
 * @param {unknown} payload
 * @param {string} pin
 * @param {{ salt?: Uint8Array, iterations?: number }} [options]
 */
export async function encryptVaultData(payload, pin, { salt, iterations = PBKDF2_ITERATIONS } = {}) {
  const actualSalt = salt ?? globalThis.crypto.getRandomValues(new Uint8Array(16));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const key = await derivePinKey(pin, actualSalt, iterations);
  const aad = new TextEncoder().encode('totp-soberano-vault-v1');
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const ciphertext = new Uint8Array(await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad },
    key,
    plaintext,
  ));
  return {
    version: 1,
    kdf: 'PBKDF2-SHA256',
    iterations,
    salt: toBase64(actualSalt),
    iv: toBase64(iv),
    ciphertext: toBase64(ciphertext),
  };
}

/**
 * Descifra el sobre cifrado de la bóveda con el PIN; lanza error si el PIN es incorrecto o hubo manipulación.
 * @param {{ version: number, iterations: number, salt: string, iv: string, ciphertext: string }} envelope
 * @param {string} pin
 */
export async function decryptVaultData(envelope, pin) {
  const salt = fromBase64(envelope.salt);
  const iv = fromBase64(envelope.iv);
  const ciphertext = fromBase64(envelope.ciphertext);
  const key = await derivePinKey(pin, salt, envelope.iterations || PBKDF2_ITERATIONS);
  const aad = new TextEncoder().encode('totp-soberano-vault-v1');
  const plainBuf = await globalThis.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, additionalData: aad },
    key,
    ciphertext,
  );
  return JSON.parse(new TextDecoder().decode(plainBuf));
}
