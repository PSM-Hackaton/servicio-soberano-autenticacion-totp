// Verificación humana (Reto 2) en el inicio de sesión del portal, sin SDK.
// El navegador resuelve la prueba de trabajo (SHA-256) que entrega el servicio Captcha a través del propio
// portal (mismo origen); el token obtenido viaja en el formulario y el portal lo valida en el servidor.
(() => {
  'use strict';
  const form = document.querySelector('form[data-captcha]');
  if (!form) return;
  const estado = form.querySelector('[data-captcha-estado]');
  const campo = form.querySelector('input[name="captcha_token"]');
  const csrf = form.querySelector('input[name="_csrf"]');
  const decir = (t) => { if (estado) estado.textContent = t; };
  const hex = (buf) => Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
  const espera = (ms) => new Promise((r) => setTimeout(r, ms));

  async function pedir(ruta, datos) {
    const cuerpo = new URLSearchParams({ _csrf: csrf ? csrf.value : '', ...datos });
    const r = await fetch(ruta, { method: 'POST', body: cuerpo, credentials: 'same-origin', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || 'Servicio de verificación no disponible');
    return j;
  }

  async function resolver() {
    const inicio = performance.now();
    decir('Comprobando que eres una persona…');
    const reto = await pedir('/captcha/reto', {});
    const objetivo = '0'.repeat(Number(reto.difficulty) || 4);
    const cod = new TextEncoder();
    let nonce = 0;
    for (;;) {
      const h = hex(await crypto.subtle.digest('SHA-256', cod.encode(`${reto.prefix}${nonce}`)));
      if (h.startsWith(objetivo)) break;
      nonce += 1;
    }
    const restante = Number(reto.min_solve_ms || 0) - (performance.now() - inicio);
    if (restante > 0) await espera(restante + 50);
    const r = await pedir('/captcha/verificar', { challenge_id: reto.challenge_id, nonce: String(nonce), hp: '' });
    return r.token;
  }

  document.addEventListener('submit', async (ev) => {
    if (ev.target !== form || (campo && campo.value)) return;
    ev.preventDefault();
    ev.stopImmediatePropagation();
    try {
      const token = await resolver();
      campo.value = token;
      decir('Verificación humana superada.');
      form.submit();
    } catch (e) {
      decir(`${e.message}. Vuelva a intentarlo.`);
    }
  }, true);
})();
