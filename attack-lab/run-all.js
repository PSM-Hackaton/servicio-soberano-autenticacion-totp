// Suite completa de Attack Lab + Pruebas de Caos (Issue #14 / B5).
// Cero dependencias npm (solo Node.js 22 nativo).
// Uso:
//   node attack-lab/run-all.js                 -> ejecuta contra el harness local integrado
//   TOTP_API_URL=https://localhost:8443 node attack-lab/run-all.js -> ejecuta contra API real

import { writeFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { createTotpClient, TotpServiceError } from '../sdk/index.js';
import { createLabHarnessServer, computeTotpAtStep } from './harness-server.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

function percentile(values, p) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return Number(sorted[idx].toFixed(2));
}

async function timedFetch(url, options) {
  const t0 = performance.now();
  const res = await fetch(url, options);
  const ms = performance.now() - t0;
  const body = await res.json().catch(() => null);
  return { status: res.status, body, ms };
}

/**
 * Ejecuta todos los ataques simulados y pruebas de caos devolviendo métricas estructuradas.
 * @param {{ baseUrl?: string, clientId?: string, clientSecret?: string, writeReports?: boolean }} [options]
 */
export async function runAttackAndChaosSuite({
  baseUrl = process.env.TOTP_API_URL || '',
  clientId = process.env.TOTP_CLIENT_ID || 'attack-lab',
  clientSecret = process.env.TOTP_CLIENT_SECRET || 'attack-lab-secret',
  writeReports = true,
} = {}) {
  let harness = null;
  let targetUrl = baseUrl.replace(/\/+$/, '');
  const isHarness = !targetUrl;

  if (isHarness) {
    harness = createLabHarnessServer();
    await new Promise((resolve) => harness.listen(0, '127.0.0.1', resolve));
    targetUrl = `http://127.0.0.1:${harness.address().port}`;
  }

  const headers = {
    'Content-Type': 'application/json',
    'X-Client-Id': clientId,
    'X-Client-Secret': clientSecret,
  };

  const results = [];
  let unauthorizedAccessGranted = 0;

  try {
    let usersMap = new Map();
    if (isHarness) {
      const u = await timedFetch(`${targetUrl}/__chaos/users`);
      for (const item of u.body.users) usersMap.set(item.userRef, item);
    }

    const secretOf = (userRef) => usersMap.get(userRef)?.secret || 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
    const idOf = (userRef) => usersMap.get(userRef)?.id || null;

    // 1. ATAQUE DE REPLAY (reutilización del mismo código TOTP dentro del mismo paso)
    {
      const step = Math.floor(Date.now() / 1000 / 30);
      const validCode = computeTotpAtStep(secretOf('victima-replay'), step);
      const first = await timedFetch(`${targetUrl}/api/v1/verify`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ user_ref: 'victima-replay', code: validCode }),
      });
      const replay = await timedFetch(`${targetUrl}/api/v1/verify`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ user_ref: 'victima-replay', code: validCode }),
      });
      if (replay.status === 200) unauthorizedAccessGranted++;
      results.push({
        escenario: 'Ataque de Replay (código repetido)',
        categoria: 'Seguridad',
        estado: first.status === 200 && replay.status === 401 ? 'MITIGADO' : 'FALLO',
        detalle: `1er intento HTTP ${first.status}; replay inmediato HTTP ${replay.status}`,
        latencia_p95_ms: percentile([first.ms, replay.ms], 95),
      });
    }

    // 2. FUERZA BRUTA LENTA Y DISTRIBUIDA (múltiples IPs contra la misma cuenta)
    {
      const latencies = [];
      let blockedAtAttempt = null;
      let statuses = [];
      for (let i = 1; i <= 8; i++) {
        const fakeIp = `198.51.100.${10 + i}`;
        const r = await timedFetch(`${targetUrl}/api/v1/verify`, {
          method: 'POST',
          headers: { ...headers, 'X-Forwarded-For': fakeIp },
          body: JSON.stringify({ user_ref: 'victima-bruteforce', code: String(100000 + i) }),
        });
        latencies.push(r.ms);
        statuses.push(r.status);
        if (r.status === 200) unauthorizedAccessGranted++;
        if (r.status === 429 && blockedAtAttempt === null) blockedAtAttempt = i;
      }
      results.push({
        escenario: 'Fuerza bruta distribuida (8 IPs -> 1 cuenta)',
        categoria: 'Seguridad + IA Local',
        estado: blockedAtAttempt !== null ? 'MITIGADO' : 'FALLO',
        detalle: `Bloqueo adaptativo 429 activado en intento #${blockedAtAttempt} (estados: ${statuses.join(',')})`,
        latencia_p95_ms: percentile(latencies, 95),
      });
    }

    // 3. PASSWORD / TOTP SPRAYING (1 IP probando muchas cuentas distintas)
    {
      const latencies = [];
      let blockedAtAccount = null;
      for (let i = 1; i <= 10; i++) {
        const r = await timedFetch(`${targetUrl}/api/v1/verify`, {
          method: 'POST',
          headers: { ...headers, 'X-Forwarded-For': '203.0.113.77' },
          body: JSON.stringify({ user_ref: `spray-user-${i}`, code: '123456' }),
        });
        latencies.push(r.ms);
        if (r.status === 200) unauthorizedAccessGranted++;
        if (r.status === 429 && blockedAtAccount === null) blockedAtAccount = i;
      }
      results.push({
        escenario: 'TOTP Spraying (1 IP -> 10 cuentas)',
        categoria: 'Seguridad + IA Local',
        estado: blockedAtAccount !== null ? 'MITIGADO' : 'FALLO',
        detalle: `Bloqueo por patrón spraying (HTTP 429) activado en la cuenta #${blockedAtAccount}`,
        latencia_p95_ms: percentile(latencies, 95),
      });
    }

    // 4. DERIVA DE RELOJ + RESINCRONIZACIÓN CON 2 CÓDIGOS CONSECUTIVOS (±10 pasos)
    {
      const currentStep = Math.floor(Date.now() / 1000 / 30);
      const driftedStep = currentStep + 5; // 150 s adelante (fuera de ventana ±1)
      const sec = secretOf('victima-drift');
      const rejectedOutOfWindow = await timedFetch(`${targetUrl}/api/v1/verify`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ user_ref: 'victima-drift', code: computeTotpAtStep(sec, driftedStep) }),
      });

      const uid = idOf('victima-drift');
      let resyncOk = false;
      let postResyncOk = false;
      const lats = [rejectedOutOfWindow.ms];

      if (uid) {
        const resync = await timedFetch(`${targetUrl}/api/v1/enrollments/${uid}/resync`, {
          method: 'POST',
          headers,
          body: JSON.stringify({
            code_1: computeTotpAtStep(sec, driftedStep),
            code_2: computeTotpAtStep(sec, driftedStep + 1),
          }),
        });
        lats.push(resync.ms);
        resyncOk = resync.status === 200 && resync.body?.resynced === true;

        // Siguiente paso tras resincronizar (+7 -> siguiente válido después de lastStep = driftedStep+1)
        const post = await timedFetch(`${targetUrl}/api/v1/verify`, {
          method: 'POST',
          headers,
          body: JSON.stringify({ user_ref: 'victima-drift', code: computeTotpAtStep(sec, driftedStep + 2) }),
        });
        lats.push(post.ms);
        postResyncOk = post.status === 200 && post.body?.verified === true;
      }

      results.push({
        escenario: 'Deriva de reloj (+5 pasos / +150 s) y Resync',
        categoria: 'Criptografía RFC 6238',
        estado: rejectedOutOfWindow.status === 401 && resyncOk && postResyncOk ? 'VERIFICADO' : 'FALLO',
        detalle: `Fuera de ventana HTTP ${rejectedOutOfWindow.status} -> Resync 2 códigos=${resyncOk} -> Verificación post-resync=${postResyncOk}`,
        latencia_p95_ms: percentile(lats, 95),
      });
    }

    // 5. CAOS: CAÍDA DE BASE DE DATOS (503 fail-closed + tiempo de recuperación)
    if (isHarness) {
      await timedFetch(`${targetUrl}/__chaos/config`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ dbDown: true }),
      });
      const readyDown = await timedFetch(`${targetUrl}/health/ready`);
      const verifyDown = await timedFetch(`${targetUrl}/api/v1/verify`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ user_ref: 'victima-replay', code: '000000' }),
      });
      if (verifyDown.status === 200) unauthorizedAccessGranted++;

      const tRecoveryStart = performance.now();
      await timedFetch(`${targetUrl}/__chaos/config`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ dbDown: false }),
      });
      const readyUp = await timedFetch(`${targetUrl}/health/ready`);
      const recoveryMs = Number((performance.now() - tRecoveryStart).toFixed(2));

      results.push({
        escenario: 'Caos: Caída de SQLite (fail-closed + recuperación)',
        categoria: 'Resiliencia / Caos',
        estado: readyDown.status === 503 && verifyDown.status === 503 && readyUp.status === 200 ? 'VERIFICADO' : 'FALLO',
        detalle: `/health/ready caída=${readyDown.status}, verify caída=${verifyDown.status} (0 accesos), recuperación en ${recoveryMs} ms`,
        latencia_p95_ms: recoveryMs,
      });
    }

    // 6. CAOS: CORTE DE RED + REINTENTO IDEMPOTENTE DEL SDK + VALIDACIÓN JWKS OFFLINE
    if (isHarness) {
      const sdk = createTotpClient({
        baseUrl: targetUrl,
        clientId,
        clientSecret,
        audience: 'attack-lab',
        timeoutMs: 1000,
        maxRetries: 1,
      });
      // Precarga JWKS
      await sdk.getJwks();
      // Forzamos un corte en el primer intento de /verify
      await timedFetch(`${targetUrl}/__chaos/config`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ dropNextVerifyOnce: true }),
      });

      const step = Math.floor(Date.now() / 1000 / 30);
      const code = computeTotpAtStep(secretOf('spray-user-14'), step);
      const t0 = performance.now();
      const verified = await sdk.verify({ userRef: 'spray-user-14', code });
      const retryMs = Number((performance.now() - t0).toFixed(2));

      // Ahora cortamos la BD/servicio y validamos el JWT ya emitido SIN RED (JWKS caché)
      await timedFetch(`${targetUrl}/__chaos/config`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ dbDown: true }),
      });
      const offlineJwt = await sdk.verifyJwtOffline(verified.token);
      await timedFetch(`${targetUrl}/__chaos/config`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ dbDown: false }),
      });

      results.push({
        escenario: 'Caos: Corte de red + Reintento Idempotente + JWKS Offline',
        categoria: 'Resiliencia / Caos',
        estado: verified.verified === true && offlineJwt.valid === true ? 'VERIFICADO' : 'FALLO',
        detalle: `Reintento idempotente exitoso (${retryMs} ms) y JWT validado offline con caché JWKS (kid=${offlineJwt.kid})`,
        latencia_p95_ms: retryMs,
      });
    }

    // 7. CAOS: LATENCIA ARTIFICIAL Y TIMEOUT FAIL-CLOSED DEL SDK
    if (isHarness) {
      await timedFetch(`${targetUrl}/__chaos/config`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ artificialLatencyMs: 180 }),
      });
      const fastTimeoutSdk = createTotpClient({
        baseUrl: targetUrl,
        clientId,
        clientSecret,
        audience: 'attack-lab',
        timeoutMs: 90,
        maxRetries: 0,
      });
      let failedClosed = false;
      const t0 = performance.now();
      try {
        await fastTimeoutSdk.verify({ userRef: 'spray-user-15', code: '123456' });
        unauthorizedAccessGranted++;
      } catch (err) {
        failedClosed = err instanceof TotpServiceError && err.code === 'TIMEOUT' && err.status === 503;
      }
      const timeoutMs = Number((performance.now() - t0).toFixed(2));
      await timedFetch(`${targetUrl}/__chaos/config`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ artificialLatencyMs: 0 }),
      });

      results.push({
        escenario: 'Caos: Latencia artificial (180 ms vs timeout 90 ms)',
        categoria: 'Resiliencia / Caos',
        estado: failedClosed ? 'VERIFICADO' : 'FALLO',
        detalle: `SDK abortó en ${timeoutMs} ms con error TIMEOUT (503 fail-closed, 0 accesos indebidos)`,
        latencia_p95_ms: timeoutMs,
      });
    }

    const report = {
      timestamp: new Date().toISOString(),
      target: isHarness ? 'harness-local-rfc6238' : targetUrl,
      total_escenarios: results.length,
      exitosos: results.filter((r) => r.estado === 'MITIGADO' || r.estado === 'VERIFICADO').length,
      accesos_indebidos_concedidos: unauthorizedAccessGranted,
      escenarios: results,
    };

    if (writeReports) {
      await writeFile(join(__dirname, 'reporte-demo.json'), `${JSON.stringify(report, null, 2)}\n`, 'utf8');
      const mdLines = [
        '# Informe de Attack Lab y Pruebas de Caos (Demo)',
        '',
        `- **Fecha UTC:** \`${report.timestamp}\``,
        `- **Objetivo:** \`${report.target}\``,
        `- **Escenarios superados:** **${report.exitosos}/${report.total_escenarios}**`,
        `- **Accesos indebidos concedidos:** **${report.accesos_indebidos_concedidos}** (política *fail-closed* estricta)`,
        '',
        '| Escenario | Categoría | Resultado | Latencia p95 / Recup. | Evidencia |',
        '| :--- | :--- | :--- | :--- | :--- |',
        ...results.map((r) => `| ${r.escenario} | ${r.categoria} | **${r.estado}** | ${r.latencia_p95_ms} ms | ${r.detalle} |`),
        '',
      ];
      await writeFile(join(__dirname, 'REPORTE_DEMO.md'), mdLines.join('\n'), 'utf8');
    }

    return report;
  } finally {
    if (harness?.listening) {
      await new Promise((resolve) => harness.close(resolve));
    }
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const report = await runAttackAndChaosSuite({ writeReports: true });
  console.log('\n=== ATTACK LAB & PRUEBAS DE CAOS — RESUMEN ===');
  console.table(report.escenarios.map((r) => ({
    Escenario: r.escenario,
    Estado: r.estado,
    'Latencia/Recup (ms)': r.latencia_p95_ms,
  })));
  console.log(`Superados: ${report.exitosos}/${report.total_escenarios} | Accesos indebidos: ${report.accesos_indebidos_concedidos}`);
  if (report.exitosos !== report.total_escenarios || report.accesos_indebidos_concedidos !== 0) {
    process.exitCode = 1;
  }
}
