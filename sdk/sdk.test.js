import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash, generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { createTotpClient, TotpServiceError } from './index.js';

function makeEd25519Key() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const { kty, crv, x } = publicKey.export({ format: 'jwk' });
  const kid = createHash('sha256').update(JSON.stringify({ crv, kty, x })).digest().subarray(0, 16).toString('base64url');
  return {
    kid,
    privateKey,
    publicJwk: { kty, crv, x, kid, use: 'sig', alg: 'EdDSA' },
  };
}

function signTestJwt({ privateKey, kid, issuer, audience, subject, ttl = 300 }) {
  const iat = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'EdDSA', typ: 'JWT', kid })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    iss: issuer,
    sub: subject,
    aud: audience,
    amr: ['otp'],
    iat,
    nbf: iat,
    exp: iat + ttl,
    jti: randomUUID(),
  })).toString('base64url');
  const sig = sign(null, Buffer.from(`${header}.${payload}`), privateKey).toString('base64url');
  return `${header}.${payload}.${sig}`;
}

test('SDK: flujo completo, timeout + 1 reintento idempotente, rotación kid y validación JWKS offline', async () => {
  const key1 = makeEd25519Key();
  const key2 = makeEd25519Key();
  let activeKeys = [key1.publicJwk];
  let verifyCalls = 0;
  const seenIdempotencyKeys = [];
  let force503 = false;

  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {};

    if (req.url === '/.well-known/jwks.json') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ keys: activeKeys }));
      return;
    }

    if (force503) {
      res.writeHead(503, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'SERVICE_UNAVAILABLE', message: 'Servicio no disponible temporalmente.' }));
      return;
    }

    if (req.headers['x-client-id'] !== 'portal-tramites' || req.headers['x-client-secret'] !== 'secret-demo') {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'UNAUTHORIZED', message: 'Credenciales inválidas.' }));
      return;
    }

    if (req.method === 'POST' && req.url === '/api/v1/enrollments') {
      res.writeHead(201, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        enrollment_id: '9f3b8c2a-6e11-4d8a-9c52-2a1d84e901ab',
        estado: 'pendiente',
        algoritmo: body.algorithm || 'SHA256',
        digitos: body.digits || 6,
        periodo: body.period || 30,
        otpauth_uri: 'otpauth://totp/MincytSoberanoTOTP:ciudadano?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=6&period=30',
        qr_svg: '<svg></svg>',
        expires_at: new Date(Date.now() + 600_000).toISOString(),
      }));
      return;
    }

    if (req.method === 'POST' && req.url === '/api/v1/verify') {
      verifyCalls++;
      seenIdempotencyKeys.push(req.headers['idempotency-key']);
      // Primera llamada simula corte / 503 transitorio; segunda responde OK
      if (verifyCalls === 1) {
        res.writeHead(503, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'SERVICE_UNAVAILABLE', message: 'Corte transitorio' }));
        return;
      }
      const token = signTestJwt({
        privateKey: key1.privateKey,
        kid: key1.kid,
        issuer: 'https://totp.soberano.local',
        audience: 'portal-tramites',
        subject: 'hmac_ciudadano',
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        verified: true,
        token,
        jti: randomUUID(),
        kid: key1.kid,
        expires_at: new Date(Date.now() + 300_000).toISOString(),
        drift_steps: 0,
        risk: { score: 5, level: 'LOW', action: 'ALLOW', inference_ms: 1.2, reasons: [] },
      }));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'NOT_FOUND', message: 'No encontrado' }));
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const sdk = createTotpClient({
      baseUrl,
      clientId: 'portal-tramites',
      clientSecret: 'secret-demo',
      issuer: 'https://totp.soberano.local',
      audience: 'portal-tramites',
      timeoutMs: 1500,
      maxRetries: 1,
    });

    // 1. Enroll
    const enr = await sdk.enroll({ userRef: 'V-12345678', algorithm: 'SHA256', digits: 6 });
    assert.equal(enr.estado, 'pendiente');

    // 2. Verify: reintenta automáticamente con la misma Idempotency-Key tras el primer 503
    const ver = await sdk.verify({ userRef: 'V-12345678', code: '123456' });
    assert.equal(ver.verified, true);
    assert.equal(verifyCalls, 2);
    assert.equal(seenIdempotencyKeys.length, 2);
    assert.ok(seenIdempotencyKeys[0]);
    assert.equal(seenIdempotencyKeys[0], seenIdempotencyKeys[1], 'Debe conservar la misma Idempotency-Key');

    // 3. Validar JWT offline usando caché JWKS (precarga y luego simula caída total de red)
    const offlineOk = await sdk.verifyJwtOffline(ver.token);
    assert.equal(offlineOk.valid, true);
    assert.equal(offlineOk.kid, key1.kid);

    // 4. Rotación de clave Ed25519: emite JWT con key2 y SDK recarga JWKS automáticamente
    activeKeys = [key2.publicJwk, key1.publicJwk];
    const rotatedToken = signTestJwt({
      privateKey: key2.privateKey,
      kid: key2.kid,
      issuer: 'https://totp.soberano.local',
      audience: 'portal-tramites',
      subject: 'hmac_ciudadano',
    });
    const rotCheck = await sdk.verifyJwtOffline(rotatedToken);
    assert.equal(rotCheck.valid, true);
    assert.equal(rotCheck.kid, key2.kid);

    // 5. Fail-closed en 503 persistente al verificar, pero JWT ya emitido sigue validándose offline!
    force503 = true;
    await assert.rejects(
      () => sdk.verify({ userRef: 'V-12345678', code: '123456' }),
      (err) => err instanceof TotpServiceError && err.status === 503,
    );

    // Apagamos el servidor por completo: verificación offline con caché JWKS sigue funcionando!
    await new Promise((resolve) => server.close(resolve));
    const stillValidOffline = await sdk.verifyJwtOffline(rotatedToken);
    assert.equal(stillValidOffline.valid, true);
  } finally {
    if (server.listening) await new Promise((resolve) => server.close(resolve));
  }
});

test('SDK: timeout estricto de petición y rechazo fail-closed', async () => {
  const slowServer = http.createServer((req, res) => {
    // Nunca responde a tiempo
    setTimeout(() => {
      if (!res.writableEnded) {
        res.writeHead(200);
        res.end('{}');
      }
    }, 500);
  });
  await new Promise((resolve) => slowServer.listen(0, '127.0.0.1', resolve));
  const { port } = slowServer.address();

  try {
    const sdk = createTotpClient({
      baseUrl: `http://127.0.0.1:${port}`,
      clientId: 'reto1-evaluador',
      clientSecret: 'secret',
      timeoutMs: 80,
      maxRetries: 1,
    });

    await assert.rejects(
      () => sdk.verify({ userRef: 'evaluador-01', code: '654321' }),
      (err) => err instanceof TotpServiceError && err.code === 'TIMEOUT' && err.status === 503,
    );
  } finally {
    await new Promise((resolve) => slowServer.close(resolve));
  }
});
