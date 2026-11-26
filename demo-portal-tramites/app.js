// Lógica cliente del Portal Institucional de Trámites (0 dependencias npm).

const $ = (id) => document.getElementById(id);

const state = {
  challengeId: null,
  usuario: null,
  enrollmentId: null,
};

function showAlert(msg, type = 'err') {
  const el = $('portal-alert');
  if (!msg) {
    el.classList.add('hidden');
    return;
  }
  el.className = `alert alert-${type}`;
  el.textContent = msg;
  el.classList.remove('hidden');
}

function setStep(step) {
  ['view-step1', 'view-step2', 'view-step3'].forEach((id, idx) => {
    $(id).classList.toggle('hidden', idx + 1 !== step);
  });
  [1, 2, 3].forEach((n) => {
    const el = $(`st-${n}`);
    el.classList.toggle('active', n === step);
    el.classList.toggle('done', n < step);
  });
}

async function apiPost(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({ message: `HTTP ${res.status}` }));
  if (!res.ok) throw new Error(data.message || `Error HTTP ${res.status}`);
  return data;
}

$('step1-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  showAlert(null);
  try {
    const res = await apiPost('/portal-api/login-step1', {
      usuario: $('p-user').value.trim(),
      password: $('p-pass').value,
    });
    state.challengeId = res.challenge_id;
    state.usuario = res.usuario;
    $('step2-greeting').textContent = `Bienvenido/a, ${res.nombre}. Ingresa el código TOTP vigente de tu PWA Autenticadora.`;
    $('p-code').value = '';
    setStep(2);
  } catch (err) {
    showAlert(err.message, 'err');
  }
});

$('step2-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  showAlert(null);
  try {
    const res = await apiPost('/portal-api/verify-step2', {
      challenge_id: state.challengeId,
      code: $('p-code').value.trim(),
    });
    $('citizen-meta').textContent = `${res.citizen.nombre} (${res.citizen.cedula}) · Factor MFA verificado con riesgo ${res.mfa.risk.level} (${res.mfa.risk.score}/100).`;
    $('tramites-list').innerHTML = res.citizen.tramites.map((t) => `
      <div class="tramite-item">
        <div>
          <strong>${t.titulo}</strong><br />
          <small class="muted">${t.codigo}</small>
        </div>
        <span class="badge">${t.estado}</span>
      </div>
    `).join('');
    $('jwt-evidence').textContent = JSON.stringify(res.mfa, null, 2);
    setStep(3);
  } catch (err) {
    showAlert(err.message, 'err');
  }
});

$('show-enroll-btn').addEventListener('click', () => {
  $('enroll-box').classList.toggle('hidden');
});

$('gen-enroll-btn').addEventListener('click', async () => {
  showAlert(null);
  try {
    const alg = $('e-alg').value;
    const res = await apiPost('/portal-api/enroll', {
      usuario: state.usuario,
      algorithm: alg,
      digits: alg === 'SHA512' ? 8 : 6,
    });
    state.enrollmentId = res.enrollment_id;
    $('qr-container').innerHTML = res.qr_svg;
    $('otpauth-box').textContent = res.otpauth_uri;
    $('enroll-result').classList.remove('hidden');
    $('recovery-box').classList.add('hidden');
  } catch (err) {
    showAlert(err.message, 'err');
  }
});

$('activate-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  showAlert(null);
  try {
    const res = await apiPost('/portal-api/activate', {
      enrollment_id: state.enrollmentId,
      code: $('act-code').value.trim(),
    });
    const box = $('recovery-box');
    box.innerHTML = `<strong>Factor activado (${res.estado}).</strong> Guarda estos 10 códigos de recuperación (se muestran una sola vez):<br><code>${res.recovery_codes.join(' · ')}</code>`;
    box.classList.remove('hidden');
    showAlert('Enrolamiento activado correctamente. Ya puedes verificar tu código en el paso 2.', 'ok');
  } catch (err) {
    showAlert(err.message, 'err');
  }
});

$('back-step1-btn').addEventListener('click', () => {
  showAlert(null);
  setStep(1);
});

$('restart-btn').addEventListener('click', () => {
  state.challengeId = null;
  state.usuario = null;
  showAlert(null);
  setStep(1);
});
