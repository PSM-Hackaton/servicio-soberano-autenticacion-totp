/**
 * @pow-captcha/client — SDK Frontend Auto-Adaptable con Animaciones Suaves
 * Detecta en tiempo real el modo configurado para la Site Key en el servidor:
 *   - 'pow'    -> Proof-of-Work SHA-256 en Web Worker inline (cero CORS)
 *   - 'image'  -> Reto visual SVG con entrada accesible y botón de refresco
 *   - 'hybrid' -> Proof-of-Work con opción de cambiar a reto de imagen
 *   - Sitio desactivado/eliminado -> Informa estado seguro vía UI y onError
 */
const WORKER_CODE = `
const encoder = new TextEncoder();
function bufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  let hex = '';
  for (let i = 0; i < bytes.length; i += 1) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

self.onmessage = async (event) => {
  const { prefix, difficulty } = event.data;
  const target = '0'.repeat(difficulty);
  const start = performance.now();
  let nonce = 0;

  while (true) {
    const data = encoder.encode(prefix + nonce);
    const digest = await crypto.subtle.digest('SHA-256', data);
    const hash = bufferToHex(digest);

    if (hash.startsWith(target)) {
      self.postMessage({
        type: 'solved',
        nonce: String(nonce),
        hash,
        attempts: nonce + 1,
        durationMs: Math.round(performance.now() - start),
      });
      return;
    }

    nonce += 1;
    if (nonce % 2500 === 0) {
      self.postMessage({
        type: 'progress',
        attempts: nonce,
        elapsedMs: Math.round(performance.now() - start),
      });
    }
  }
};
`;

let cachedWorkerBlobUrl = null;
function getInlineWorkerUrl() {
  if (!cachedWorkerBlobUrl) {
    const blob = new Blob([WORKER_CODE], { type: 'application/javascript' });
    cachedWorkerBlobUrl = URL.createObjectURL(blob);
  }
  return cachedWorkerBlobUrl;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export class PowCaptchaClient {
  constructor(container, options = {}) {
    this.container = typeof container === 'string' ? document.querySelector(container) : container;
    if (!this.container) {
      throw new Error(`[PowCaptchaClient] Contenedor no encontrado: ${container}`);
    }

    this.siteKey = options.siteKey || this.container.dataset?.sitekey || null;
    this.apiBase = (options.apiBase || 'http://localhost:3000/api/captcha').replace(/\/$/, '');
    this.onVerified = options.onVerified || null;
    this.onError = options.onError || null;
    this.minSolveMs = Number.isFinite(options.minSolveMs) ? options.minSolveMs : 1600;

    this.token = null;
    this.worker = null;
    this.activeChallenge = null;

    this.render();
  }

  ensureStyles() {
    if (document.getElementById('pow-captcha-keyframes')) return;
    const style = document.createElement('style');
    style.id = 'pow-captcha-keyframes';
    style.textContent = `
      @keyframes pow-spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
      }
      @keyframes pow-check-pop {
        0% { transform: scale(0) rotate(-45deg); opacity: 0; }
        70% { transform: scale(1.2) rotate(5deg); opacity: 1; }
        100% { transform: scale(1) rotate(0deg); opacity: 1; }
      }
      @keyframes pow-pulse-glow {
        0% { box-shadow: 0 0 0 0 rgba(56, 189, 248, 0.4); }
        70% { box-shadow: 0 0 0 8px rgba(56, 189, 248, 0); }
        100% { box-shadow: 0 0 0 0 rgba(56, 189, 248, 0); }
      }
      @keyframes pow-verified-glow {
        0% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.5); }
        50% { box-shadow: 0 0 16px 2px rgba(34, 197, 94, 0.4); }
        100% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0); }
      }
      .pow-spinner {
        width: 18px;
        height: 18px;
        border: 2.5px solid rgba(56, 189, 248, 0.25);
        border-top-color: #38bdf8;
        border-radius: 50%;
        animation: pow-spin 0.75s cubic-bezier(0.4, 0, 0.2, 1) infinite;
      }
      .pow-check-svg {
        animation: pow-check-pop 0.35s cubic-bezier(0.175, 0.885, 0.32, 1.275) forwards;
      }
      .pow-btn-check:hover:not(:disabled) {
        border-color: #38bdf8 !important;
        background: rgba(56, 189, 248, 0.08) !important;
        transform: scale(1.04);
      }
      .pow-btn-check {
        transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
      }
    `;
    document.head.appendChild(style);
  }

  render() {
    this.ensureStyles();

    this.container.innerHTML = `
      <div class="pow-captcha-box" data-state="idle" style="
        font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        background: #0f172a;
        color: #f8fafc;
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 14px 16px;
        display: flex;
        flex-direction: column;
        gap: 10px;
        max-width: 390px;
        box-shadow: 0 4px 14px rgba(0,0,0,0.22);
        transition: border-color 0.3s ease, box-shadow 0.3s ease;
      ">
        <div style="display: flex; align-items: center; justify-content: space-between; gap: 12px;">
          <div style="display: flex; align-items: center; gap: 12px;">
            <button type="button" class="pow-btn-check" style="
              width: 32px;
              height: 32px;
              border-radius: 8px;
              border: 2px solid #64748b;
              background: #1e293b;
              cursor: pointer;
              display: grid;
              place-items: center;
              color: #f8fafc;
              padding: 0;
              position: relative;
            " aria-label="Verificar que no eres un bot">
              <span class="pow-check-icon" style="display: grid; place-items: center; width: 100%; height: 100%;"></span>
            </button>
            <div style="display: flex; flex-direction: column;">
              <span class="pow-title" style="font-size: 14px; font-weight: 600; letter-spacing: -0.01em;">No soy un robot</span>
              <span class="pow-subtitle" style="font-size: 11px; color: #94a3b8; transition: color 0.2s ease;">Verificación Soberana</span>
            </div>
          </div>
          <span class="pow-mode-badge" style="font-size: 10px; font-weight: 700; color: #38bdf8; background: rgba(56,189,248,0.1); border: 1px solid rgba(56,189,248,0.35); padding: 3px 8px; border-radius: 99px; letter-spacing: 0.04em;">
            AUTO
          </span>
        </div>

        <div class="pow-progress-wrap" style="height: 4px; background: #1e293b; border-radius: 99px; overflow: hidden; display: none;">
          <div class="pow-progress-fill" style="height: 100%; width: 0%; background: linear-gradient(90deg, #38bdf8, #818cf8); border-radius: 99px; transition: width 0.18s ease;"></div>
        </div>

        <!-- Panel dinámico para modo Imagen -->
        <div class="pow-image-panel" style="display: none; flex-direction: column; gap: 8px; padding-top: 8px; border-top: 1px solid #1e293b;">
          <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px;">
            <div class="pow-svg-wrap" style="background: #ffffff; border-radius: 8px; padding: 4px; display: inline-flex; overflow: hidden; box-shadow: 0 2px 6px rgba(0,0,0,0.15);"></div>
            <button type="button" class="pow-btn-refresh" style="background: #1e293b; color: #e2e8f0; border: 1px solid #334155; border-radius: 6px; padding: 6px 10px; font-size: 11.5px; cursor: pointer; transition: background 0.2s ease;">Otra imagen</button>
          </div>
          <div style="display: flex; gap: 8px;">
            <input type="text" class="pow-image-input" placeholder="Escribe los caracteres" autocomplete="off" style="flex: 1; background: #1e293b; color: #f8fafc; border: 1px solid #475569; border-radius: 6px; padding: 7px 10px; font-size: 13px; letter-spacing: 0.12em; outline: none; transition: border-color 0.2s;" />
            <button type="button" class="pow-btn-verify-img" style="background: #2563eb; color: #ffffff; border: none; border-radius: 6px; padding: 7px 14px; font-size: 12.5px; font-weight: 600; cursor: pointer; transition: background 0.2s ease;">Validar</button>
          </div>
        </div>

        <div class="pow-status-msg" style="font-size: 11px; color: #94a3b8; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; display: none;"></div>

        <!-- Honeypot invisible -->
        <div aria-hidden="true" style="position: absolute; left: -10000px; width: 1px; height: 1px; overflow: hidden;">
          <input type="text" name="pow_hp" class="pow-input-hp" tabindex="-1" autocomplete="off" />
        </div>
      </div>
    `;

    this.root = this.container.querySelector('.pow-captcha-box');
    this.btn = this.container.querySelector('.pow-btn-check');
    this.icon = this.container.querySelector('.pow-check-icon');
    this.title = this.container.querySelector('.pow-title');
    this.subtitle = this.container.querySelector('.pow-subtitle');
    this.modeBadge = this.container.querySelector('.pow-mode-badge');
    this.progressWrap = this.container.querySelector('.pow-progress-wrap');
    this.progressFill = this.container.querySelector('.pow-progress-fill');
    this.imagePanel = this.container.querySelector('.pow-image-panel');
    this.svgWrap = this.container.querySelector('.pow-svg-wrap');
    this.imageInput = this.container.querySelector('.pow-image-input');
    this.btnVerifyImg = this.container.querySelector('.pow-btn-verify-img');
    this.btnRefreshImg = this.container.querySelector('.pow-btn-refresh');
    this.statusMsg = this.container.querySelector('.pow-status-msg');
    this.hpInput = this.container.querySelector('.pow-input-hp');

    this.btn.addEventListener('click', () => this.execute());
    this.btnVerifyImg.addEventListener('click', () => this.submitImageSolution());
    this.btnRefreshImg.addEventListener('click', () => this.execute('image'));
    this.imageInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        this.submitImageSolution();
      }
    });
  }

  setSpinnerState() {
    this.btn.disabled = true;
    this.btn.style.borderColor = '#38bdf8';
    this.btn.style.background = '#0f172a';
    this.btn.style.animation = 'pow-pulse-glow 1.5s infinite';
    this.icon.innerHTML = '<div class="pow-spinner"></div>';
  }

  async fetchChallenge(requestedType = undefined) {
    const body = { site_key: this.siteKey };
    if (requestedType) body.type = requestedType;

    const res = await fetch(`${this.apiBase}/challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(data.error || `HTTP ${res.status}`);
      err.code = data.code || `HTTP_${res.status}`;
      throw err;
    }

    data.receivedAt = Date.now();
    return data;
  }

  async execute(requestedType = undefined) {
    if (this.root.dataset.state === 'solving' || this.root.dataset.state === 'verified') return;

    this.token = null;
    this.activeChallenge = null;
    this.root.dataset.state = 'solving';
    this.setSpinnerState();

    this.imagePanel.style.display = 'none';
    this.progressWrap.style.display = 'block';
    this.progressFill.style.width = '15%';
    this.statusMsg.style.display = 'block';
    this.statusMsg.textContent = 'Verificando seguridad del sitio...';

    try {
      const challenge = await this.fetchChallenge(requestedType);
      this.activeChallenge = challenge;

      const modeLabel =
        challenge.type === 'image'
          ? 'IMAGEN'
          : challenge.site_mode === 'hybrid'
            ? 'HÍBRIDO'
            : 'AUTOMÁTICO';
      this.modeBadge.textContent = modeLabel;

      if (challenge.type === 'image') {
        this.btn.style.animation = 'none';
        this.progressWrap.style.display = 'none';
        this.root.dataset.state = 'awaiting_image';
        this.icon.innerHTML = '';
        this.btn.style.borderColor = '#818cf8';
        this.title.textContent = 'Completa el código visual';
        this.subtitle.textContent = 'Modo imagen activo para este sitio';
        this.statusMsg.textContent = 'Escribe los caracteres mostrados y pulsa Validar.';
        this.svgWrap.textContent = '';
        const imgElem = document.createElement('img');
        imgElem.alt = 'Desafío de caracteres visuales';
        imgElem.style.display = 'block';
        imgElem.src = `data:image/svg+xml;utf8,${encodeURIComponent(challenge.image || '')}`;
        this.svgWrap.appendChild(imgElem);
        this.imageInput.value = '';
        this.imagePanel.style.display = 'flex';
        this.imageInput.focus();
        return;
      }

      // Flujo de protección automática
      this.statusMsg.textContent = 'Comprobando seguridad...';
      const solution = await this.solvePoW(challenge);

      const elapsed = Date.now() - challenge.receivedAt;
      // El servidor no publica su tiempo mínimo: sin el dato se espera el mínimo por defecto (MIN_SOLVE_MS=1500) con margen.
      const minimo = Number.isFinite(challenge.min_solve_ms) ? challenge.min_solve_ms : this.minSolveMs;
      const waitTime = minimo - elapsed + 100;
      if (waitTime > 0) {
        this.statusMsg.textContent = 'Confirmando con el servidor...';
        await sleep(waitTime);
      }

      await this.verifyWithServer({
        challenge_id: challenge.challenge_id,
        nonce: solution.nonce,
        hp: this.hpInput.value,
      }, `Completado en ${solution.durationMs} ms`, `Hash: ${solution.hash.slice(0, 16)}...`);
    } catch (err) {
      this.handleError(err);
    }
  }

  async submitImageSolution() {
    if (!this.activeChallenge || this.activeChallenge.type !== 'image') return;
    const solution = this.imageInput.value.trim();
    if (!solution) {
      this.statusMsg.textContent = 'Ingresa los caracteres de la imagen.';
      this.imageInput.focus();
      return;
    }

    this.btnVerifyImg.disabled = true;
    this.setSpinnerState();
    this.statusMsg.textContent = 'Validando respuesta...';

    try {
      await this.verifyWithServer({
        challenge_id: this.activeChallenge.challenge_id,
        solution,
        hp: this.hpInput.value,
      }, 'Verificado por imagen', 'Reto visual completado con éxito');
      this.imagePanel.style.display = 'none';
    } catch (err) {
      this.btn.style.animation = 'none';
      this.icon.innerHTML = '';
      this.btn.style.borderColor = '#ef4444';
      this.statusMsg.textContent = err.message || 'Código incorrecto, intenta de nuevo.';
      this.imageInput.value = '';
      this.imageInput.focus();
      if (typeof this.onError === 'function') this.onError(err);
    } finally {
      this.btnVerifyImg.disabled = false;
    }
  }

  async verifyWithServer(payload, subtitleText, statusText) {
    const verifyRes = await fetch(`${this.apiBase}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    const verifyData = await verifyRes.json().catch(() => ({}));
    if (!verifyRes.ok || !verifyData.success) {
      throw new Error(verifyData.error || 'Verificación fallida');
    }

    this.token = verifyData.token;
    this.root.dataset.state = 'verified';

    // Animación de éxito espectacular
    this.btn.style.animation = 'pow-verified-glow 0.8s ease-out';
    this.btn.style.borderColor = '#22c55e';
    this.btn.style.background = '#22c55e';
    this.root.style.borderColor = 'rgba(34, 197, 94, 0.4)';
    this.root.style.boxShadow = '0 6px 20px rgba(34, 197, 94, 0.15)';

    this.icon.innerHTML = `
      <svg class="pow-check-svg" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#0f172a" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round">
        <polyline points="20 6 9 17 4 12"></polyline>
      </svg>
    `;

    this.title.textContent = 'Verificado';
    this.subtitle.textContent = subtitleText;
    this.subtitle.style.color = '#86efac';
    this.progressWrap.style.display = 'block';
    this.progressFill.style.width = '100%';
    this.progressFill.style.background = '#22c55e';
    this.statusMsg.textContent = statusText;

    // Inyectar o actualizar el token en el input hidden del formulario más cercano
    const form = this.container.closest('form');
    if (form) {
      let input = form.querySelector('input[name="captcha_token"]') || form.querySelector('#captcha_token');
      if (!input) {
        input = document.createElement('input');
        input.type = 'hidden';
        input.name = 'captcha_token';
        form.appendChild(input);
      }
      input.value = this.token;
    }

    if (typeof this.onVerified === 'function') {
      this.onVerified(this.token);
    }
  }

  handleError(err) {
    this.btn.style.animation = 'none';
    const disabled = err.code === 'SITE_DISABLED' || err.code === 'SITE_DELETED';
    this.btn.disabled = disabled;
    this.root.dataset.state = disabled ? 'disabled' : 'error';
    this.btn.style.borderColor = disabled ? '#f59e0b' : '#ef4444';
    this.btn.style.background = '#1e293b';
    this.icon.innerHTML = disabled
      ? '<span style="font-size:14px; color:#f59e0b;">&#9888;</span>'
      : '<span style="font-size:14px; color:#ef4444; font-weight:bold;">&times;</span>';
    this.modeBadge.textContent = disabled ? 'INACTIVO' : 'ERROR';
    this.title.textContent = disabled ? 'CAPTCHA desactivado' : 'Error de verificación';
    this.subtitle.textContent = err.message;
    this.subtitle.style.color = disabled ? '#fbbf24' : '#f87171';
    this.progressWrap.style.display = 'none';
    this.statusMsg.style.display = 'block';
    this.statusMsg.textContent = disabled
      ? 'El administrador pausó o eliminó este sitio.'
      : 'Haz clic para reintentar.';

    if (typeof this.onError === 'function') {
      this.onError(err);
    }
  }

  solvePoW({ prefix, difficulty }) {
    return new Promise((resolve, reject) => {
      const workerUrl = getInlineWorkerUrl();
      this.worker = new Worker(workerUrl);

      const expectedAttempts = Math.pow(16, difficulty);

      this.worker.onmessage = (event) => {
        const msg = event.data;
        if (msg.type === 'progress') {
          const pct = Math.min(95, Math.round((msg.attempts / expectedAttempts) * 100));
          this.progressFill.style.width = `${pct}%`;
          this.statusMsg.textContent = `${msg.attempts.toLocaleString()} hashes...`;
        } else if (msg.type === 'solved') {
          this.worker.terminate();
          this.worker = null;
          resolve(msg);
        }
      };

      this.worker.onerror = (err) => {
        this.worker.terminate();
        this.worker = null;
        reject(new Error(err.message || 'Error en Web Worker'));
      };

      this.worker.postMessage({ prefix, difficulty });
    });
  }

  reset() {
    if (this.worker) {
      this.worker.terminate();
      this.worker = null;
    }
    this.token = null;
    this.activeChallenge = null;
    this.btn.disabled = false;
    this.btn.style.animation = 'none';
    this.btn.style.borderColor = '#64748b';
    this.btn.style.background = '#1e293b';
    this.icon.innerHTML = '';
    this.root.style.borderColor = '#334155';
    this.root.style.boxShadow = '0 4px 14px rgba(0,0,0,0.22)';
    this.title.textContent = 'No soy un robot';
    this.subtitle.textContent = 'Verificación Soberana';
    this.subtitle.style.color = '#94a3b8';
    this.modeBadge.textContent = 'AUTO';
    this.imagePanel.style.display = 'none';
    this.progressWrap.style.display = 'none';
    this.progressFill.style.width = '0%';
    this.statusMsg.style.display = 'none';
    this.root.dataset.state = 'idle';
  }
}

export function autoInit() {
  if (typeof document === 'undefined') return;
  document.querySelectorAll('.pow-captcha').forEach((el) => {
    if (!el._powInstance) {
      el._powInstance = new PowCaptchaClient(el);
    }
  });
}

if (typeof window !== 'undefined') {
  window.PowCaptchaClient = PowCaptchaClient;
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', autoInit);
  } else {
    autoInit();
  }
}
