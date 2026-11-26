// Controlador UI de la Consola Administrativa (HTML + CSS + JS nativo, sin dependencias).

import { createAdminClient, getPermissions } from './admin-api.js';

const client = createAdminClient({ mode: 'mock', baseUrl: 'https://localhost:8443' });
const $ = (id) => document.getElementById(id);

function showFeedback(message, type = 'ok') {
  const box = $('global-feedback');
  box.className = `alert alert-${type}`;
  box.textContent = message;
  box.classList.remove('hidden');
  clearTimeout(showFeedback._t);
  showFeedback._t = setTimeout(() => box.classList.add('hidden'), 5000);
}

function syncConnInputs() {
  const mode = $('data-mode').value;
  const baseUrl = $('api-url').value.trim() || 'https://localhost:8443';
  client.setConfig({ mode, baseUrl });
  $('mock-role-wrap').classList.toggle('hidden', mode !== 'mock');
  $('tamper-demo-btn').classList.toggle('hidden', mode !== 'mock');
}

function applyRbacToUi() {
  const session = client.getSession();
  if (!session) return;
  const perms = getPermissions(session.rol);
  $('session-badge').textContent = `${session.usuario} · ${session.rol}`;
  $('session-badge').classList.remove('hidden');
  $('logout-btn').classList.remove('hidden');

  $('create-app-btn').disabled = !perms.manageApps;
  $('apps-rbac-note').classList.toggle('hidden', perms.manageApps);
  $('rotate-keys-btn').disabled = !perms.rotateKeys;
}

function switchSection(name) {
  document.querySelectorAll('.nav-btn').forEach((b) => b.classList.toggle('active', b.dataset.section === name));
  document.querySelectorAll('.panel-section').forEach((s) => s.classList.toggle('hidden', s.id !== `sec-${name}`));
}

async function loadOverview() {
  const { healthReady, anomalies, metrics, metricsRaw } = await client.getOverview();
  const avail = metrics.gauges.totp_availability_percent ?? 100;
  const p95 = metrics.latency['/api/v1/verify']?.p95 ?? '-';
  const skew = metrics.gauges.totp_clock_skew_ms ?? healthReady?.checks?.clock_skew_ms ?? 0;
  const avgInf = metrics.gauges.totp_anomaly_inference_ms_avg ?? anomalies?.summary?.avgInferenceMs ?? 0;
  const blockedTotal = (metrics.verifications.replay || 0) + (metrics.verifications.anomaly_blocked || 0) + (metrics.verifications.locked || 0);

  const kpis = [
    {
      label: 'Disponibilidad / Ready',
      val: `${avail}%`,
      sub: healthReady?.ready ? 'SQLite OK · Ed25519 OK' : 'NO LISTO (503)',
    },
    {
      label: 'Latencia Verify p95',
      val: p95 === '-' ? 'N/A' : `${p95} ms`,
      sub: 'Objetivo institucional < 200 ms',
    },
    {
      label: 'Bloqueos (Replay + IA)',
      val: String(blockedTotal),
      sub: `Inferencia IA media: ${avgInf} ms`,
    },
    {
      label: 'Desfase de reloj',
      val: `${skew} ms`,
      sub: skew > 2000 ? '⚠ ALERTA: supera 2000 ms' : 'Reloj soberano sincronizado',
    },
  ];

  $('kpi-grid').innerHTML = kpis.map((k) => `
    <div class="kpi">
      <div class="label">${k.label}</div>
      <div class="val">${k.val}</div>
      <div class="sub">${k.sub}</div>
    </div>
  `).join('');

  const alerts = anomalies?.alerts || [];
  $('alerts-tbody').innerHTML = alerts.length
    ? alerts.map((a) => `
      <tr>
        <td class="mono">${a.createdAt || a.created_at || '-'}</td>
        <td class="mono">${a.externalUserId || a.user_ref_hash || '-'}</td>
        <td class="mono">${a.ipHash || a.ip_hash || '-'}</td>
        <td><span class="badge badge-danger">${a.riskScore ?? a.score} (${a.level})</span></td>
        <td><strong>${a.action}</strong></td>
        <td>${(a.reasons || []).join(' · ')}</td>
      </tr>
    `).join('')
    : '<tr><td colspan="6" class="muted">Sin alertas de anomalía registradas.</td></tr>';

  $('metrics-raw').textContent = metricsRaw;
}

async function loadApps() {
  const { apps = [] } = await client.getApps();
  $('apps-tbody').innerHTML = apps.map((a) => `
    <tr>
      <td><strong>${a.nombre}</strong></td>
      <td class="mono">${a.client_id}</td>
      <td>${a.algoritmo} · ${a.digitos} dígitos · ${a.periodo}s (±${a.ventana ?? 1})</td>
      <td>Máx ${a.max_intentos} intentos · IA ≥ ${a.umbral_riesgo_bloqueo} (${a.modo_heuristica})</td>
      <td><span class="badge ${a.estado === 'activo' ? 'badge-ok' : 'badge-warn'}">${a.estado}</span></td>
    </tr>
  `).join('');
}

async function loadEnrollments() {
  const perms = getPermissions(client.getSession()?.rol);
  const { enrollments = [] } = await client.getEnrollments();
  $('enrollments-tbody').innerHTML = enrollments.map((e) => {
    const badge = e.estado === 'activo' ? 'badge-ok' : e.estado === 'pendiente' ? 'badge-warn' : 'badge-danger';
    const disabled = !perms.revokeEnrollment || e.estado === 'revocado';
    return `
      <tr>
        <td class="mono">${e.id.slice(0, 8)}…</td>
        <td>${e.app_nombre || e.app_id}</td>
        <td class="mono">${e.user_ref_hash}</td>
        <td>${e.algoritmo} · ${e.digitos}d</td>
        <td>${e.drift_steps >= 0 ? `+${e.drift_steps}` : e.drift_steps} pasos</td>
        <td><span class="badge ${badge}">${e.estado}</span></td>
        <td>
          <button class="btn btn-danger" data-revoke="${e.id}" ${disabled ? 'disabled' : ''}>
            ${e.estado === 'revocado' ? 'Revocado' : 'Revocar'}
          </button>
        </td>
      </tr>
    `;
  }).join('');

  $('enrollments-tbody').querySelectorAll('button[data-revoke]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      try {
        await client.revokeEnrollment(btn.dataset.revoke);
        showFeedback(`Enrolamiento ${btn.dataset.revoke.slice(0, 8)}… revocado definitivamente.`);
        await Promise.all([loadEnrollments(), loadAudit()]);
      } catch (err) {
        showFeedback(err.message, 'danger');
      }
    });
  });
}

async function loadKeys() {
  const { keys = [] } = await client.getJwks();
  $('keys-tbody').innerHTML = keys.map((k, idx) => `
    <tr>
      <td class="mono"><strong>${k.kid}</strong></td>
      <td>${k.alg} / ${k.crv}</td>
      <td class="mono">${k.x}</td>
      <td><span class="badge ${idx === 0 ? 'badge-ok' : 'badge-info'}">${idx === 0 ? 'Activa (firma)' : 'Ventana de gracia (verificación)'}</span></td>
    </tr>
  `).join('');
}

async function loadAudit() {
  const { events = [] } = await client.getAudit();
  $('audit-tbody').innerHTML = events.map((ev) => `
    <tr>
      <td>${ev.id}</td>
      <td class="mono">${ev.ts}</td>
      <td>${ev.actor}</td>
      <td><span class="badge badge-info">${ev.accion}</span></td>
      <td class="mono">${ev.objetivo || '-'}</td>
      <td class="mono">${String(ev.prev_hash).slice(0, 10)}… → ${String(ev.hash).slice(0, 10)}…</td>
    </tr>
  `).join('');
}

async function refreshAll() {
  try {
    await Promise.all([loadOverview(), loadApps(), loadEnrollments(), loadKeys(), loadAudit()]);
  } catch (err) {
    showFeedback(`Error cargando datos: ${err.message}`, 'danger');
  }
}

function bindEvents() {
  $('data-mode').addEventListener('change', () => {
    syncConnInputs();
    if (client.getSession()) refreshAll();
  });

  $('api-url').addEventListener('change', syncConnInputs);

  $('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    $('login-error').classList.add('hidden');
    syncConnInputs();
    try {
      await client.login({
        usuario: $('l-user').value.trim(),
        password: $('l-pass').value,
        totp_code: $('l-totp').value.trim(),
        mockRol: $('l-role').value,
      });
      $('login-view').classList.add('hidden');
      $('dashboard-view').classList.remove('hidden');
      applyRbacToUi();
      await refreshAll();
    } catch (err) {
      $('login-error').textContent = err.message;
      $('login-error').classList.remove('hidden');
    }
  });

  $('logout-btn').addEventListener('click', () => {
    client.logout();
    $('dashboard-view').classList.add('hidden');
    $('login-view').classList.remove('hidden');
    $('session-badge').classList.add('hidden');
    $('logout-btn').classList.add('hidden');
  });

  document.querySelectorAll('.nav-btn').forEach((btn) => {
    btn.addEventListener('click', () => switchSection(btn.dataset.section));
  });

  $('refresh-overview-btn').addEventListener('click', () => loadOverview().catch((e) => showFeedback(e.message, 'danger')));
  $('refresh-enroll-btn').addEventListener('click', () => loadEnrollments().catch((e) => showFeedback(e.message, 'danger')));

  $('app-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const res = await client.createApp({
        nombre: $('a-name').value.trim(),
        client_id: $('a-client').value.trim(),
        algoritmo: $('a-alg').value,
        digitos: Number($('a-digits').value),
        umbral_riesgo_bloqueo: Number($('a-threshold').value),
        modo_heuristica: $('a-mode').value,
        permitir_sha1: $('a-alg').value === 'SHA1',
      });
      const secretBox = $('created-secret-box');
      secretBox.innerHTML = `<strong>Aplicación registrada.</strong> Guarda este secreto ahora (no volverá a mostrarse):<br><code>client_id: ${res.client_id}</code> · <code>client_secret: ${res.client_secret || '(generado en servidor)'}</code>`;
      secretBox.classList.remove('hidden');
      $('a-name').value = '';
      $('a-client').value = '';
      await Promise.all([loadApps(), loadAudit()]);
    } catch (err) {
      showFeedback(err.message, 'danger');
    }
  });

  $('rotate-keys-btn').addEventListener('click', async () => {
    try {
      const res = await client.rotateKeys();
      showFeedback(`Rotación exitosa: nueva llave activa ${res.new_kid} (anterior ${res.previous_kid} en ventana de gracia).`);
      await Promise.all([loadKeys(), loadAudit()]);
    } catch (err) {
      showFeedback(err.message, 'danger');
    }
  });

  $('verify-chain-btn').addEventListener('click', async () => {
    try {
      const res = await client.verifyAuditChain();
      const box = $('chain-result');
      box.classList.remove('hidden');
      if (res.intact) {
        box.className = 'alert alert-ok';
        box.textContent = `✔ CADENA ÍNTEGRA: ${res.checked_records} registros verificados sin alteraciones. Último hash: ${res.last_hash}`;
      } else {
        box.className = 'alert alert-danger';
        box.textContent = `✖ ALTERACIÓN DETECTADA en el registro #${res.broken_at_id} (evaluados ${res.checked_records}). La cadena de hashes está rota.`;
      }
    } catch (err) {
      showFeedback(err.message, 'danger');
    }
  });

  $('tamper-demo-btn').addEventListener('click', async () => {
    if (client.simulateMockAuditTamper()) {
      await loadAudit();
      showFeedback('Se alteró el prev_hash del registro #2 (demo). Pulsa "Verificar integridad de la cadena" para ver la detección.', 'warn');
    }
  });
}

syncConnInputs();
bindEvents();
