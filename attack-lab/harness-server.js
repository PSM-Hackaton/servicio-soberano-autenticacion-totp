// Servidor de banco de pruebas local (harness) para ejecutar attack-lab y caos 100% offline
// antes de integrar contra el backend real en staging. Cero dependencias npm.

import http from 'node:http';
import { createHash, createHmac, generateKeyPairSync, randomUUID, sign } from 'node:crypto';

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
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

export function computeTotpAtStep(secretBase32, step, algorithm = 'SHA256', digits = 6) {
  const alg = algorithm === 'SHA512' ? 'sha512' : algorithm === 'SHA1' ? 'sha1' : 'sha256';
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(step));
  const mac = createHmac(alg, fromBase32(secretBase32)).update(msg).digest();
  const off = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
  return String(bin % (10 ** digits)).padStart(digits, '0');
}

export function createLabHarnessServer() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const { kty, crv, x } = publicKey.export({ format: 'jwk' });
  const kid = createHash('sha256').update(JSON.stringify({ crv, kty, x })).digest().subarray(0, 16).toString('base64url');
  const jwks = { keys: [{ kty, crv, x, kid, use: 'sig', alg: 'EdDSA' }] };

  const chaos = {
    dbDown: false,
    artificialLatencyMs: 0,
    dropNextVerifyOnce: false,
  };

  const enrollments = new Map();
  const idempotencyStore = new Map();
  const attemptsByAccount = new Map(); // user_ref -> [{ ts, ip, ok }]
  const attemptsByIp = new Map();      // ip -> Set<user_ref>

  function seedUser(userRef, secret = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP') {
    const id = randomUUID();
    enrollments.set(userRef, {
      id,
      userRef,
      secret,
      algorithm: 'SHA256',
      digits: 6,
      period: 30,
      lastStep: -1,
      driftSteps: 0,
      failedAttempts: 0,
      lockedUntilMs: 0,
    });
    return enrollments.get(userRef);
  }

  seedUser('victima-replay');
  seedUser('victima-bruteforce');
  seedUser('victima-drift');
  for (let i = 1; i <= 15; i++) seedUser(`spray-user-${i}`);

  function issueJwt(userRef) {
    const iat = Math.floor(Date.now() / 1000);
    const jti = randomUUID();
    const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT', kid })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({
      iss: 'https://totp.soberano.local',
      sub: `hmac_${createHash('sha256').update(userRef).digest('hex').slice(0, 12)}`,
      aud: 'attack-lab',
      amr: ['otp'],
      iat,
      nbf: iat,
      exp: iat + 300,
      jti,
    })).toString('base64url');
    const sig = sign(null, Buffer.from(`${header}.${payload}`), privateKey).toString('base64url');
    return { token: `${header}.${payload}.${sig}`, jti, kid };
  }

  const send = (res, status, obj, extraHeaders = {}) => {
    res.writeHead(status, { 'Content-Type': 'application/json', ...extraHeaders });
    res.end(JSON.stringify(obj));
  };

  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};

    // Controles de caos locales del harness
    if (req.url === '/__chaos/config' && req.method === 'POST') {
      if (typeof body.dbDown === 'boolean') chaos.dbDown = body.dbDown;
      if (typeof body.artificialLatencyMs === 'number') chaos.artificialLatencyMs = body.artificialLatencyMs;
      if (typeof body.dropNextVerifyOnce === 'boolean') chaos.dropNextVerifyOnce = body.dropNextVerifyOnce;
      send(res, 200, { ok: true, chaos });
      return;
    }

    if (req.url === '/__chaos/users' && req.method === 'GET') {
      const list = [...enrollments.values()].map((e) => ({ id: e.id, userRef: e.userRef, secret: e.secret, driftSteps: e.driftSteps }));
      send(res, 200, { users: list });
      return;
    }

    if (chaos.artificialLatencyMs > 0) {
      await new Promise((r) => setTimeout(r, chaos.artificialLatencyMs));
    }

    if (req.url === '/.well-known/jwks.json') {
      send(res, 200, jwks);
      return;
    }

    if (req.url === '/health/ready') {
      if (chaos.dbDown) {
        send(res, 503, { error: 'SERVICE_UNAVAILABLE', message: 'Servicio no disponible temporalmente.' });
      } else {
        send(res, 200, { status: 'ready', ready: true, timestamp: new Date().toISOString(), checks: { sqlite: true, signing_key: true, clock_skew_ms: 8 } });
      }
      return;
    }

    if (chaos.dbDown) {
      send(res, 503, { error: 'SERVICE_UNAVAILABLE', message: 'Servicio no disponible temporalmente.' });
      return;
    }

    if (req.url === '/api/v1/verify' && req.method === 'POST') {
      if (chaos.dropNextVerifyOnce) {
        chaos.dropNextVerifyOnce = false;
        send(res, 503, { error: 'SERVICE_UNAVAILABLE', message: 'Corte de red simulado' });
        return;
      }

      const idemKey = req.headers['idempotency-key'];
      if (idemKey && idempotencyStore.has(idemKey)) {
        const cached = idempotencyStore.get(idemKey);
        send(res, cached.status, cached.body, { 'Idempotency-Key': String(idemKey) });
        return;
      }

      const ip = String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1').split(',')[0].trim();
      const { user_ref, code } = body;
      const enr = enrollments.get(user_ref);
      const nowMs = Date.now();

      // Seguimiento conductual local (simula heuristics/)
      const ipUsers = attemptsByIp.get(ip) || new Set();
      ipUsers.add(user_ref);
      attemptsByIp.set(ip, ipUsers);

      const accHist = attemptsByAccount.get(user_ref) || [];
      const recentAcc = accHist.filter((a) => nowMs - a.ts < 60_000);
      const distinctIps = new Set(recentAcc.map((a) => a.ip));
      distinctIps.add(ip);

      // Detección de spraying (>6 cuentas distintas desde la misma IP) o fuerza bruta distribuida (>=4 IPs distintas con fallos)
      if (ipUsers.size >= 6) {
        send(res, 429, { error: 'TOO_MANY_REQUESTS', message: 'Demasiados intentos. Intente más tarde.', retry_after_seconds: 120 }, { 'Retry-After': '120' });
        return;
      }
      if (distinctIps.size >= 4 && recentAcc.filter((a) => !a.ok).length >= 4) {
        send(res, 429, { error: 'TOO_MANY_REQUESTS', message: 'Demasiados intentos. Intente más tarde.', retry_after_seconds: 300 }, { 'Retry-After': '300' });
        return;
      }

      if (!enr) {
        send(res, 401, { error: 'VERIFICATION_FAILED', message: 'No se pudo completar la verificación.' });
        return;
      }

      if (enr.lockedUntilMs > nowMs) {
        const retry = Math.ceil((enr.lockedUntilMs - nowMs) / 1000);
        send(res, 429, { error: 'TOO_MANY_REQUESTS', message: 'Demasiados intentos. Intente más tarde.', retry_after_seconds: retry }, { 'Retry-After': String(retry) });
        return;
      }

      const currentStep = Math.floor(nowMs / 1000 / enr.period);
      const centerStep = currentStep + enr.driftSteps;
      let matchedStep = null;
      for (const delta of [0, -1, 1]) {
        if (computeTotpAtStep(enr.secret, centerStep + delta, enr.algorithm, enr.digits) === String(code)) {
          matchedStep = centerStep + delta;
          break;
        }
      }

      if (matchedStep === null || matchedStep <= enr.lastStep) {
        enr.failedAttempts++;
        recentAcc.push({ ts: nowMs, ip, ok: false });
        attemptsByAccount.set(user_ref, recentAcc);
        // Bloqueo progresivo (30s, 2m, 10m, 1h) a partir del 5to fallo
        if (enr.failedAttempts >= 5) {
          const escalon = [30, 120, 600, 3600][Math.min(enr.failedAttempts - 5, 3)];
          enr.lockedUntilMs = nowMs + escalon * 1000;
          send(res, 429, { error: 'TOO_MANY_REQUESTS', message: 'Demasiados intentos. Intente más tarde.', retry_after_seconds: escalon }, { 'Retry-After': String(escalon) });
          return;
        }
        send(res, 401, { error: 'VERIFICATION_FAILED', message: 'No se pudo completar la verificación.' });
        return;
      }

      enr.lastStep = matchedStep;
      enr.driftSteps = matchedStep - currentStep;
      enr.failedAttempts = 0;
      recentAcc.push({ ts: nowMs, ip, ok: true });
      attemptsByAccount.set(user_ref, recentAcc);

      const jwt = issueJwt(user_ref);
      const responseBody = {
        verified: true,
        token: jwt.token,
        jti: jwt.jti,
        kid: jwt.kid,
        expires_at: new Date(nowMs + 300_000).toISOString(),
        drift_steps: enr.driftSteps,
        risk: { score: 7.5, level: 'LOW', action: 'ALLOW', inference_ms: 1.4, reasons: [] },
      };
      if (idemKey) idempotencyStore.set(idemKey, { status: 200, body: responseBody });
      send(res, 200, responseBody, idemKey ? { 'Idempotency-Key': String(idemKey) } : {});
      return;
    }

    const resyncMatch = req.url?.match(/^\/api\/v1\/enrollments\/([^/]+)\/resync$/);
    if (resyncMatch && req.method === 'POST') {
      const id = resyncMatch[1];
      const enr = [...enrollments.values()].find((e) => e.id === id);
      if (!enr) {
        send(res, 401, { error: 'VERIFICATION_FAILED', message: 'No se pudo completar la verificación.' });
        return;
      }
      const { code_1, code_2 } = body;
      const currentStep = Math.floor(Date.now() / 1000 / enr.period);
      for (let drift = -10; drift <= 10; drift++) {
        const s1 = currentStep + drift;
        const c1 = computeTotpAtStep(enr.secret, s1, enr.algorithm, enr.digits);
        const c2 = computeTotpAtStep(enr.secret, s1 + 1, enr.algorithm, enr.digits);
        if (c1 === String(code_1) && c2 === String(code_2) && s1 + 1 > enr.lastStep) {
          enr.driftSteps = drift + 1;
          enr.lastStep = s1 + 1;
          send(res, 200, { resynced: true, drift_steps: enr.driftSteps });
          return;
        }
      }
      send(res, 401, { error: 'VERIFICATION_FAILED', message: 'No se pudo completar la verificación.' });
      return;
    }

    send(res, 404, { error: 'NOT_FOUND', message: 'Ruta no encontrada.' });
  });

  return server;
}
