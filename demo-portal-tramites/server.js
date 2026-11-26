// Servidor del Portal Institucional de Trámites Demo (0 dependencias npm, Node.js 22 nativo).
// Conecta contra la API real vía sdk/ si TOTP_API_URL está definido, o usa un adaptador local
// criptográficamente real (RFC 6238 + JWT Ed25519 + JWKS) para demostración standalone inmediata.

import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, createHmac, generateKeyPairSync, randomBytes, randomUUID, sign } from 'node:crypto';
import { createTotpClient, verifyJwtWithJwks, TotpServiceError } from '../sdk/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = normalize(join(__dirname, '..'));

const MIME_TYPES = Object.freeze({
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
});

// Ciudadanos demo del Portal de Trámites (solo para demostración académica del reto)
const DEMO_CITIZENS = Object.freeze({
  'ciudadano-demo': {
    password: 'Tramites2026!',
    nombre: 'María Fernanda Pérez',
    cedula: 'V-18.452.910',
    tramites: [
      { codigo: 'TRM-2026-00412', titulo: 'Constancia de Residencia Electrónica', estado: 'Aprobado' },
      { codigo: 'TRM-2026-00895', titulo: 'Apostilla Digital de Título Universitario', estado: 'En revisión' },
    ],
  },
  'evaluador-01': {
    password: 'Reto12026!',
    nombre: 'Carlos Eduardo Mendoza (Reto 1)',
    cedula: 'V-21.304.118',
    tramites: [
      { codigo: 'PROP-2026-104', titulo: 'Evaluación de Propuesta de Servicio Público #104', estado: 'Pendiente firma MFA' },
    ],
  },
});

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function toBase32(buf) {
  let bits = 0; let val = 0; let out = '';
  for (const b of buf) {
    val = (val << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(val >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(val << (5 - bits)) & 31];
  return out;
}

function fromBase32(str) {
  const clean = str.toUpperCase().replace(/[\s-]+/g, '').replace(/=+$/g, '');
  let bits = 0; let val = 0; const out = [];
  for (const ch of clean) {
    const idx = BASE32.indexOf(ch);
    if (idx === -1) throw new Error('Base32 inválido');
    val = (val << 5) | idx;
    bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}

function computeHotpNode(secretBuf, counter, algorithm = 'SHA256', digits = 6) {
  const alg = algorithm === 'SHA512' ? 'sha512' : algorithm === 'SHA1' ? 'sha1' : 'sha256';
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac(alg, secretBuf).update(msg).digest();
  const off = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
  return String(bin % (10 ** digits)).padStart(digits, '0');
}

/**
 * Crea un backend MFA embebido en memoria para demos sin servidor remoto (100% RFC 6238 + Ed25519 real).
 */
function createStandaloneMfaAdapter() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const { kty, crv, x } = publicKey.export({ format: 'jwk' });
  const kid = createHash('sha256').update(JSON.stringify({ crv, kty, x })).digest().subarray(0, 16).toString('base64url');
  const jwks = { keys: [{ kty, crv, x, kid, use: 'sig', alg: 'EdDSA' }] };

  const enrollments = new Map();
  const consumedJtis = new Set();

  // Semilla pre-enrolada compatible con el botón "Cargar cuentas demo" de authenticator-app/
  enrollments.set('ciudadano-demo', {
    enrollment_id: '9f3b8c2a-6e11-4d8a-9c52-2a1d84e901ab',
    userRef: 'ciudadano-demo',
    secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
    algorithm: 'SHA256',
    digits: 6,
    period: 30,
    estado: 'activo',
    lastStep: -1,
    recoveryCodes: new Set(['A7K9-M2P4', 'B3X8-Q5W2', 'C9N4-R7T1']),
  });

  function issueJwt(userRef) {
    const iat = Math.floor(Date.now() / 1000);
    const jti = randomUUID();
    const sub = `hmac_${createHash('sha256').update(userRef).digest('hex').slice(0, 16)}`;
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT', kid })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      iss: 'https://totp.soberano.local',
      sub,
      aud: 'portal-tramites',
      amr: ['otp'],
      iat,
      nbf: iat,
      exp: iat + 300,
      jti,
    })).toString('base64url');
    const sig = sign(null, Buffer.from(`${header}.${payload}`), privateKey).toString('base64url');
    return { token: `${header}.${payload}.${sig}`, jti, kid, expires_at: new Date((iat + 300) * 1000).toISOString() };
  }

  return {
    mode: 'standalone-crypto',
    getJwks: async () => jwks,
    async enroll({ userRef, accountLabel, algorithm = 'SHA256', digits = 6, period = 30 }) {
      const seedBytes = randomBytes(algorithm === 'SHA512' ? 64 : 32);
      const secret = toBase32(seedBytes);
      const enrollment_id = randomUUID();
      const label = encodeURIComponent(`MincytSoberanoTOTP:${accountLabel || userRef}`);
      const otpauth_uri = `otpauth://totp/${label}?secret=${secret}&issuer=MincytSoberanoTOTP&algorithm=${algorithm}&digits=${digits}&period=${period}`;
      const qr_svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 220 220" width="180" height="180"><rect width="220" height="220" rx="12" fill="#ffffff"/><rect x="16" y="16" width="52" height="52" fill="#0b1220"/><rect x="24" y="24" width="36" height="36" fill="#fff"/><rect x="32" y="32" width="20" height="20" fill="#0f766e"/><rect x="152" y="16" width="52" height="52" fill="#0b1220"/><rect x="160" y="24" width="36" height="36" fill="#fff"/><rect x="168" y="32" width="20" height="20" fill="#0f766e"/><rect x="16" y="152" width="52" height="52" fill="#0b1220"/><rect x="24" y="160" width="36" height="36" fill="#fff"/><rect x="32" y="168" width="20" height="20" fill="#0f766e"/><text x="110" y="114" text-anchor="middle" font-family="monospace" font-size="11" fill="#0b1220">TOTP ${algorithm}/${digits}d</text><text x="110" y="132" text-anchor="middle" font-family="monospace" font-size="9" fill="#0f766e">Usar URI o Base32</text></svg>`;

      enrollments.set(userRef, {
        enrollment_id,
        userRef,
        secret,
        algorithm,
        digits,
        period,
        estado: 'pendiente',
        lastStep: -1,
        recoveryCodes: new Set(),
      });

      return {
        enrollment_id,
        estado: 'pendiente',
        algoritmo: algorithm,
        digitos: digits,
        periodo: period,
        secret_base32_demo: secret,
        otpauth_uri,
        qr_svg,
        expires_at: new Date(Date.now() + 10 * 60_000).toISOString(),
      };
    },

    async activate(enrollmentId, code) {
      const enr = [...enrollments.values()].find((e) => e.enrollment_id === enrollmentId);
      if (!enr) throw new TotpServiceError('No se pudo completar la verificación.', { status: 401, code: 'VERIFICATION_FAILED' });
      const step = Math.floor(Date.now() / 1000 / enr.period);
      const secretBuf = fromBase32(enr.secret);
      const matched = [-1, 0, 1].some((d) => computeHotpNode(secretBuf, step + d, enr.algorithm, enr.digits) === String(code));
      if (!matched) throw new TotpServiceError('No se pudo completar la verificación.', { status: 401, code: 'VERIFICATION_FAILED' });

      enr.estado = 'activo';
      enr.lastStep = step;
      const codes = Array.from({ length: 10 }, () => {
        const raw = randomBytes(4).toString('hex').toUpperCase();
        return `${raw.slice(0, 4)}-${raw.slice(4)}`;
      });
      enr.recoveryCodes = new Set(codes);
      return {
        enrollment_id: enr.enrollment_id,
        estado: 'activo',
        activated_at: new Date().toISOString(),
        recovery_codes: codes,
      };
    },

    async verify({ userRef, code }) {
      const enr = enrollments.get(userRef);
      if (!enr || enr.estado !== 'activo') {
        throw new TotpServiceError('No se pudo completar la verificación.', { status: 401, code: 'VERIFICATION_FAILED' });
      }
      const step = Math.floor(Date.now() / 1000 / enr.period);
      const secretBuf = fromBase32(enr.secret);
      let matchedStep = null;
      for (const delta of [0, -1, 1]) {
        if (computeHotpNode(secretBuf, step + delta, enr.algorithm, enr.digits) === String(code)) {
          matchedStep = step + delta;
          break;
        }
      }
      if (matchedStep === null || matchedStep <= enr.lastStep) {
        throw new TotpServiceError('No se pudo completar la verificación.', { status: 401, code: 'VERIFICATION_FAILED' });
      }
      enr.lastStep = matchedStep;
      const jwt = issueJwt(userRef);
      return {
        verified: true,
        ...jwt,
        drift_steps: matchedStep - step,
        risk: { score: 6.2, level: 'LOW', action: 'ALLOW', inference_ms: 1.1, reasons: ['Verificación legítima RFC 6238'] },
      };
    },

    async validateToken(token, { consumeJti = true } = {}) {
      const check = verifyJwtWithJwks(token, {
        jwks,
        issuer: 'https://totp.soberano.local',
        audience: 'portal-tramites',
      });
      if (!check.valid) return { valid: false, reason: check.reason };
      if (consumeJti) {
        if (consumedJtis.has(check.jti)) return { valid: false, reason: 'jti_consumed' };
        consumedJtis.add(check.jti);
      }
      return {
        valid: true,
        sub: check.sub,
        aud: check.aud,
        jti: check.jti,
        kid: check.kid,
        amr: check.amr,
        exp: check.exp,
      };
    },

    async verifyJwtOffline(token) {
      return verifyJwtWithJwks(token, {
        jwks,
        issuer: 'https://totp.soberano.local',
        audience: 'portal-tramites',
      });
    },

    async recover({ userRef, recoveryCode }) {
      const enr = enrollments.get(userRef);
      if (!enr || !enr.recoveryCodes.has(String(recoveryCode).trim().toUpperCase())) {
        throw new TotpServiceError('No se pudo completar la verificación.', { status: 401, code: 'VERIFICATION_FAILED' });
      }
      enr.recoveryCodes.delete(String(recoveryCode).trim().toUpperCase());
      return { recovered: true, must_reenroll: true, remaining_codes: enr.recoveryCodes.size };
    },
  };
}

function sendJson(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-store',
  });
  res.end(JSON.stringify(data));
}

async function readJsonBody(req) {
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > 64 * 1024) throw new Error('Cuerpo demasiado grande');
    chunks.push(c);
  }
  if (!chunks.length) return {};
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

async function serveStatic(res, baseDir, relPath) {
  const safeRel = relPath === '/' || relPath === '' ? 'index.html' : relPath.replace(/^\/+/, '');
  const fullPath = normalize(join(baseDir, safeRel));
  if (!fullPath.startsWith(baseDir)) {
    sendJson(res, 403, { error: 'FORBIDDEN', message: 'Ruta inválida' });
    return;
  }
  try {
    const data = await readFile(fullPath);
    const mime = MIME_TYPES[extname(fullPath)] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': mime, 'X-Content-Type-Options': 'nosniff' });
    res.end(data);
  } catch {
    sendJson(res, 404, { error: 'NOT_FOUND', message: 'Recurso no encontrado' });
  }
}

/**
 * Crea el servidor HTTP del Portal de Trámites Demo.
 * @param {{ apiUrl?: string, clientId?: string, clientSecret?: string }} [options]
 */
export function createPortalServer({
  apiUrl = process.env.TOTP_API_URL || '',
  clientId = process.env.TOTP_CLIENT_ID || 'portal-tramites',
  clientSecret = process.env.TOTP_CLIENT_SECRET || 'demo-portal-secret',
} = {}) {
  const mfa = apiUrl
    ? createTotpClient({ baseUrl: apiUrl, clientId, clientSecret, audience: clientId })
    : createStandaloneMfaAdapter();

  const pendingLogins = new Map();

  return http.createServer(async (req, res) => {
    const url = new URL(req.url || '/', 'http://localhost');
    const pathname = url.pathname;

    try {
      // API del Portal Demo
      if (pathname === '/portal-api/status' && req.method === 'GET') {
        sendJson(res, 200, {
          portal: 'Portal Institucional de Trámites (Demo)',
          mfaMode: apiUrl ? 'live-sdk' : 'standalone-crypto',
          apiUrl: apiUrl || null,
        });
        return;
      }

      if (pathname === '/portal-api/login-step1' && req.method === 'POST') {
        const { usuario, password } = await readJsonBody(req);
        const citizen = DEMO_CITIZENS[usuario];
        if (!citizen || citizen.password !== password) {
          sendJson(res, 401, { error: 'INVALID_CREDENTIALS', message: 'Usuario o contraseña incorrectos.' });
          return;
        }
        const challengeId = randomUUID();
        pendingLogins.set(challengeId, { usuario, createdAt: Date.now() });
        sendJson(res, 200, {
          challenge_id: challengeId,
          usuario,
          nombre: citizen.nombre,
          mfa_required: true,
        });
        return;
      }

      if (pathname === '/portal-api/enroll' && req.method === 'POST') {
        const { usuario, algorithm = 'SHA256', digits = 6 } = await readJsonBody(req);
        if (!DEMO_CITIZENS[usuario]) {
          sendJson(res, 400, { error: 'INVALID_USER', message: 'Usuario demo no reconocido.' });
          return;
        }
        const resEnroll = await mfa.enroll({
          userRef: usuario,
          accountLabel: usuario,
          algorithm,
          digits: Number(digits),
          period: 30,
        });
        sendJson(res, 201, resEnroll);
        return;
      }

      if (pathname === '/portal-api/activate' && req.method === 'POST') {
        const { enrollment_id, code } = await readJsonBody(req);
        const activated = await mfa.activate(enrollment_id, code);
        sendJson(res, 200, activated);
        return;
      }

      if (pathname === '/portal-api/verify-step2' && req.method === 'POST') {
        const { challenge_id, code } = await readJsonBody(req);
        const pending = pendingLogins.get(challenge_id);
        if (!pending) {
          sendJson(res, 401, { error: 'CHALLENGE_EXPIRED', message: 'Inicia nuevamente el paso 1.' });
          return;
        }
        const verifyRes = await mfa.verify({ userRef: pending.usuario, code });
        // Validamos el JWT con el SDK (verificación offline JWKS + validación de consumo jti)
        const jwtOffline = await mfa.verifyJwtOffline(verifyRes.token);
        const jwtOnline = await mfa.validateToken(verifyRes.token, { consumeJti: true });
        if (!jwtOffline.valid || !jwtOnline.valid) {
          sendJson(res, 401, { error: 'INVALID_MFA_TOKEN', message: 'El comprobante JWT MFA no superó la validación.' });
          return;
        }
        pendingLogins.delete(challenge_id);
        const citizen = DEMO_CITIZENS[pending.usuario];
        sendJson(res, 200, {
          authenticated: true,
          citizen: { usuario: pending.usuario, nombre: citizen.nombre, cedula: citizen.cedula, tramites: citizen.tramites },
          mfa: {
            verified: verifyRes.verified,
            kid: verifyRes.kid,
            jti: verifyRes.jti,
            drift_steps: verifyRes.drift_steps,
            risk: verifyRes.risk,
            jwt_offline_valid: jwtOffline.valid,
            jwt_jti_consumed: jwtOnline.valid,
            amr: jwtOnline.amr || ['otp'],
            token_preview: `${verifyRes.token.slice(0, 46)}…`,
          },
        });
        return;
      }

      if (pathname === '/portal-api/recover' && req.method === 'POST') {
        const { usuario, recovery_code } = await readJsonBody(req);
        const rec = await mfa.recover({ userRef: usuario, recoveryCode: recovery_code });
        sendJson(res, 200, rec);
        return;
      }

      // Rutas estáticas convenientes para lanzar todo el ecosistema desde 1 solo comando sin Docker
      if (pathname.startsWith('/authenticator')) {
        const sub = pathname.replace(/^\/authenticator\/?/, '') || 'index.html';
        await serveStatic(res, join(REPO_ROOT, 'authenticator-app'), sub);
        return;
      }
      if (pathname.startsWith('/admin')) {
        const sub = pathname.replace(/^\/admin\/?/, '') || 'index.html';
        await serveStatic(res, join(REPO_ROOT, 'admin-console'), sub);
        return;
      }
      if (pathname.startsWith('/contracts/mocks')) {
        const sub = pathname.replace(/^\/contracts\/mocks\/?/, '');
        await serveStatic(res, join(REPO_ROOT, 'contracts', 'mocks'), sub);
        return;
      }

      await serveStatic(res, __dirname, pathname);
    } catch (err) {
      const status = err instanceof TotpServiceError ? err.status : 500;
      sendJson(res, status, {
        error: err?.code || 'PORTAL_ERROR',
        message: err?.message || 'Error procesando la solicitud.',
      });
    }
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORTAL_PORT || 3000);
  const server = createPortalServer();
  server.listen(port, '127.0.0.1', () => {
    console.log(`[Portal Trámites Demo] Activo en http://127.0.0.1:${port}`);
    console.log(`  · Portal de Trámites:     http://127.0.0.1:${port}/`);
    console.log(`  · PWA Autenticadora:      http://127.0.0.1:${port}/authenticator/`);
    console.log(`  · Consola Administrativa: http://127.0.0.1:${port}/admin/`);
  });
}
