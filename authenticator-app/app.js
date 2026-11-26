// Controlador principal de la PWA Autenticadora Soberana (100% JS nativo, sin frameworks ni CDNs).

import { generateTotp, parseOtpAuthUri, decodeBase32 } from './totp-core.js';
import { hasVault, saveVaultAccounts, unlockVaultAccounts, wipeVault } from './vault-idb.js';

const RING_CIRCUMFERENCE = 2 * Math.PI * 22; // r = 22

const state = {
  pin: null,
  vaultExists: false,
  accounts: [],
  tickTimer: null,
  qrStream: null,
  qrLoopActive: false,
};

const $ = (id) => document.getElementById(id);

function showToast(msg) {
  const el = $('toast');
  el.textContent = msg;
  el.classList.remove('hidden');
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => el.classList.add('hidden'), 2200);
}

function setError(id, msg) {
  const el = $(id);
  if (!msg) {
    el.textContent = '';
    el.classList.add('hidden');
  } else {
    el.textContent = msg;
    el.classList.remove('hidden');
  }
}

function formatCode(code) {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}

function updateNetworkBadge() {
  const pill = $('offline-pill');
  if (navigator.onLine) {
    pill.textContent = '● 100% Local (SW activo)';
    pill.classList.remove('warn');
  } else {
    pill.textContent = '● Modo Sin Conexión';
    pill.classList.add('warn');
  }
}

async function init() {
  updateNetworkBadge();
  window.addEventListener('online', updateNetworkBadge);
  window.addEventListener('offline', updateNetworkBadge);

  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('./sw.js').catch(() => {});
  }

  state.vaultExists = await hasVault();
  renderPinScreen();
  bindEvents();
  setInterval(() => {
    $('local-clock').textContent = new Date().toLocaleTimeString();
  }, 1000);
  $('local-clock').textContent = new Date().toLocaleTimeString();
}

function renderPinScreen() {
  $('pin-view').classList.remove('hidden');
  $('vault-view').classList.add('hidden');
  $('pin-input').value = '';
  $('pin-confirm').value = '';
  setError('pin-error', null);

  if (state.vaultExists) {
    $('pin-title').textContent = 'Desbloquear bóveda soberana';
    $('pin-subtitle').textContent = 'Ingresa tu PIN para descifrar las semillas TOTP almacenadas localmente en IndexedDB.';
    $('pin-confirm-wrap').classList.add('hidden');
    $('pin-submit-btn').textContent = 'Desbloquear';
    $('wipe-vault-btn').classList.remove('hidden');
  } else {
    $('pin-title').textContent = 'Protege tus semillas con PIN';
    $('pin-subtitle').innerHTML = 'Las semillas se cifran en tu dispositivo con <strong>AES-256-GCM</strong> y clave derivada por <strong>PBKDF2-SHA256</strong>. Ningún dato sale de tu equipo.';
    $('pin-confirm-wrap').classList.remove('hidden');
    $('pin-submit-btn').textContent = 'Crear bóveda cifrada';
    $('wipe-vault-btn').classList.add('hidden');
  }
}

function openVaultView() {
  $('pin-view').classList.add('hidden');
  $('vault-view').classList.remove('hidden');
  renderAccounts();
  startTicker();
}

function lockVault() {
  stopQrScanner();
  clearInterval(state.tickTimer);
  state.pin = null;
  state.accounts = [];
  $('add-panel').classList.add('hidden');
  renderPinScreen();
  showToast('Bóveda bloqueada');
}

function startTicker() {
  clearInterval(state.tickTimer);
  refreshCodes();
  state.tickTimer = setInterval(refreshCodes, 500);
}

function renderAccounts() {
  const list = $('accounts-list');
  list.innerHTML = '';
  if (state.accounts.length === 0) {
    $('empty-state').classList.remove('hidden');
    return;
  }
  $('empty-state').classList.add('hidden');

  for (const acc of state.accounts) {
    const card = document.createElement('article');
    card.className = 'account-card';
    card.dataset.id = acc.id;
    card.title = 'Toca para copiar el código TOTP';
    card.innerHTML = `
      <div>
        <div class="account-meta">
          <span class="issuer"></span>
          <span class="algo-tag ${acc.algorithm === 'SHA1' ? 'sha1' : ''}"></span>
        </div>
        <div class="account-name"></div>
        <div class="totp-code" data-role="code">------</div>
        <div class="mini-actions">
          <button type="button" class="mini-btn" data-action="copy">Copiar código</button>
          <button type="button" class="mini-btn" data-action="delete">Eliminar</button>
        </div>
      </div>
      <div class="ring-wrap">
        <div class="ring">
          <svg viewBox="0 0 56 56" aria-hidden="true">
            <circle class="ring-bg" cx="28" cy="28" r="22"></circle>
            <circle class="ring-fg" cx="28" cy="28" r="22"
              stroke-dasharray="${RING_CIRCUMFERENCE.toFixed(2)}"
              stroke-dashoffset="0"></circle>
          </svg>
          <span class="ring-label" data-role="rem">--</span>
        </div>
      </div>
    `;
    card.querySelector('.issuer').textContent = acc.issuer;
    card.querySelector('.algo-tag').textContent = `${acc.algorithm} · ${acc.digits}d · ${acc.period}s`;
    card.querySelector('.account-name').textContent = acc.account;

    card.addEventListener('click', async (e) => {
      const btn = e.target.closest('button[data-action]');
      if (btn?.dataset.action === 'delete') {
        e.stopPropagation();
        await removeAccount(acc.id);
        return;
      }
      const rawCode = card.dataset.rawCode;
      if (rawCode) await copyText(rawCode);
    });
    list.appendChild(card);
  }
  refreshCodes();
}

async function refreshCodes() {
  const now = Date.now();
  const cards = $('accounts-list').querySelectorAll('.account-card');
  for (const card of cards) {
    const acc = state.accounts.find((a) => a.id === card.dataset.id);
    if (!acc) continue;
    try {
      const res = await generateTotp(acc.secret, {
        algorithm: acc.algorithm,
        digits: acc.digits,
        period: acc.period,
        timestampMs: now,
      });
      card.dataset.rawCode = res.code;
      const codeEl = card.querySelector('[data-role="code"]');
      const remEl = card.querySelector('[data-role="rem"]');
      const fgEl = card.querySelector('.ring-fg');
      codeEl.textContent = formatCode(res.code);
      remEl.textContent = `${res.remainingSeconds}s`;

      const ratio = res.remainingSeconds / res.period;
      fgEl.style.strokeDashoffset = String(RING_CIRCUMFERENCE * (1 - ratio));
      const expiring = res.remainingSeconds <= 5;
      codeEl.classList.toggle('expiring', expiring);
      fgEl.classList.toggle('expiring', expiring);
    } catch {
      card.querySelector('[data-role="code"]').textContent = 'ERROR';
    }
  }
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    showToast(`Código ${formatCode(text)} copiado`);
  } catch {
    showToast(`Código: ${formatCode(text)}`);
  }
}

async function addAccount(accountData) {
  const item = {
    id: crypto.randomUUID(),
    issuer: accountData.issuer.trim() || 'Institución Soberana',
    account: accountData.account.trim() || 'usuario',
    secret: accountData.secret.toUpperCase().replace(/[\s-]+/g, ''),
    algorithm: accountData.algorithm || 'SHA256',
    digits: Number(accountData.digits) || 6,
    period: Number(accountData.period) || 30,
    createdAt: new Date().toISOString(),
  };
  decodeBase32(item.secret); // valida antes de guardar
  state.accounts.push(item);
  await saveVaultAccounts(state.accounts, state.pin);
  $('add-panel').classList.add('hidden');
  renderAccounts();
  showToast('Cuenta cifrada y guardada');
}

async function removeAccount(id) {
  state.accounts = state.accounts.filter((a) => a.id !== id);
  await saveVaultAccounts(state.accounts, state.pin);
  renderAccounts();
  showToast('Cuenta eliminada de la bóveda');
}

async function startQrScanner() {
  setError('add-error', null);
  if (!('BarcodeDetector' in window)) {
    setError('add-error', 'Este navegador no expone BarcodeDetector para cámara. Pega la URI otpauth:// arriba o usa Clave manual Base32.');
    return;
  }
  try {
    const detector = new window.BarcodeDetector({ formats: ['qr_code'] });
    state.qrStream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
    const video = $('qr-video');
    video.srcObject = state.qrStream;
    await video.play();
    $('qr-scanner-wrap').classList.remove('hidden');
    $('stop-qr-btn').classList.remove('hidden');
    state.qrLoopActive = true;

    const scanFrame = async () => {
      if (!state.qrLoopActive) return;
      try {
        const codes = await detector.detect(video);
        for (const c of codes) {
          if (c.rawValue && c.rawValue.toLowerCase().startsWith('otpauth://totp/')) {
            stopQrScanner();
            const parsed = parseOtpAuthUri(c.rawValue);
            await addAccount(parsed);
            return;
          }
        }
      } catch {
        // continuar escaneando
      }
      requestAnimationFrame(scanFrame);
    };
    requestAnimationFrame(scanFrame);
  } catch (err) {
    stopQrScanner();
    setError('add-error', `No se pudo abrir la cámara (${err.message}). Usa el pegado de URI otpauth:// o clave manual Base32.`);
  }
}

function stopQrScanner() {
  state.qrLoopActive = false;
  if (state.qrStream) {
    state.qrStream.getTracks().forEach((t) => t.stop());
    state.qrStream = null;
  }
  $('qr-scanner-wrap')?.classList.add('hidden');
  $('stop-qr-btn')?.classList.add('hidden');
}

function bindEvents() {
  $('pin-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    setError('pin-error', null);
    const pin = $('pin-input').value.trim();
    try {
      if (!state.vaultExists) {
        const confirm = $('pin-confirm').value.trim();
        if (pin !== confirm) {
          setError('pin-error', 'Los PIN no coinciden.');
          return;
        }
        await saveVaultAccounts([], pin);
        state.vaultExists = true;
        state.pin = pin;
        state.accounts = [];
        openVaultView();
        showToast('Bóveda AES-256-GCM creada');
      } else {
        const accounts = await unlockVaultAccounts(pin);
        state.pin = pin;
        state.accounts = accounts || [];
        openVaultView();
      }
    } catch {
      setError('pin-error', 'PIN incorrecto o bóveda dañada. Intenta nuevamente.');
    }
  });

  $('wipe-vault-btn').addEventListener('click', async () => {
    if (!window.confirm('¿Eliminar definitivamente la bóveda local cifrada? Esta acción no se puede deshacer.')) return;
    await wipeVault();
    state.vaultExists = false;
    state.pin = null;
    state.accounts = [];
    renderPinScreen();
    showToast('Bóveda restablecida');
  });

  $('lock-btn').addEventListener('click', lockVault);

  $('toggle-add-btn').addEventListener('click', () => {
    $('add-panel').classList.toggle('hidden');
    setError('add-error', null);
  });

  $('cancel-add-btn').addEventListener('click', () => {
    stopQrScanner();
    $('add-panel').classList.add('hidden');
  });

  $('m-alg').addEventListener('change', (e) => {
    $('sha1-warn').classList.toggle('hidden', e.target.value !== 'SHA1');
  });

  document.querySelectorAll('.tab').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach((b) => b.classList.remove('active'));
      btn.classList.add('active');
      const isManual = btn.dataset.tab === 'manual';
      $('manual-form').classList.toggle('hidden', !isManual);
      $('uri-panel').classList.toggle('hidden', isManual);
      if (isManual) stopQrScanner();
    });
  });

  $('manual-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    setError('add-error', null);
    try {
      await addAccount({
        issuer: $('m-issuer').value,
        account: $('m-account').value,
        secret: $('m-secret').value,
        algorithm: $('m-alg').value,
        digits: Number($('m-digits').value),
        period: Number($('m-period').value),
      });
      $('m-account').value = '';
      $('m-secret').value = '';
    } catch (err) {
      setError('add-error', err.message);
    }
  });

  $('uri-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    setError('add-error', null);
    try {
      const parsed = parseOtpAuthUri($('u-uri').value);
      await addAccount(parsed);
      $('u-uri').value = '';
    } catch (err) {
      setError('add-error', err.message);
    }
  });

  $('scan-qr-btn').addEventListener('click', startQrScanner);
  $('stop-qr-btn').addEventListener('click', stopQrScanner);

  $('load-demo-btn').addEventListener('click', async () => {
    const demos = [
      {
        issuer: 'MincytSoberanoTOTP',
        account: 'portal-tramites · ciudadano-demo',
        secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
        algorithm: 'SHA256',
        digits: 6,
        period: 30,
      },
      {
        issuer: 'MincytSoberanoTOTP',
        account: 'reto1-evaluador · evaluador-01',
        secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
        algorithm: 'SHA512',
        digits: 8,
        period: 30,
      },
    ];
    for (const d of demos) {
      if (!state.accounts.some((a) => a.account === d.account)) {
        await addAccount(d);
      }
    }
    showToast('Cuentas demo institucionales listas');
  });
}

init();
