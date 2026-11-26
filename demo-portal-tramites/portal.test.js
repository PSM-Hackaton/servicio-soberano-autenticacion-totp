import test from 'node:test';
import assert from 'node:assert/strict';
import { createPortalServer } from './server.js';
import { generateTotp } from '../authenticator-app/totp-core.js';

test('Portal de Trámites Demo: flujo completo usuario+clave -> código TOTP PWA -> JWT Ed25519 validado', async () => {
  const server = createPortalServer({ apiUrl: '' });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;

  try {
    // Paso 1: usuario + clave
    const r1 = await fetch(`${base}/portal-api/login-step1`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ usuario: 'ciudadano-demo', password: 'Tramites2026!' }),
    });
    assert.equal(r1.status, 200);
    const step1 = await r1.json();
    assert.equal(step1.mfa_required, true);

    // Generar código TOTP real usando el motor Web Crypto de authenticator-app/
    const { code } = await generateTotp('JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP', {
      algorithm: 'SHA256',
      digits: 6,
      period: 30,
    });

    // Paso 2: verificar código y emitir + validar JWT Ed25519
    const r2 = await fetch(`${base}/portal-api/verify-step2`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challenge_id: step1.challenge_id, code }),
    });
    assert.equal(r2.status, 200);
    const step2 = await r2.json();
    assert.equal(step2.authenticated, true);
    assert.equal(step2.mfa.jwt_offline_valid, true);
    assert.equal(step2.mfa.jwt_jti_consumed, true);
    assert.deepEqual(step2.mfa.amr, ['otp']);

    // Verificar que sirve la PWA y la Consola Admin en el mismo servidor local
    const pwaRes = await fetch(`${base}/authenticator/index.html`);
    assert.equal(pwaRes.status, 200);
    const adminRes = await fetch(`${base}/admin/index.html`);
    assert.equal(adminRes.status, 200);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
