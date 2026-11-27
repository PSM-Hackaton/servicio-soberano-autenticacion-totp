// Verificación humana (Reto 2) en el ingreso: monta el widget del SDK @pow-captcha/client (instalado en
// vendor/ desde la consola del servicio) contra el intermediario de mismo origen del portal (/captcha/api).
// El SDK deja el token en el campo oculto captcha_token; el servidor lo valida con @pow-captcha/server.
import { PowCaptchaClient } from '/vendor/pow-captcha-client/dist/index.js';

const form = document.querySelector('form[data-captcha]');
const caja = document.getElementById('captcha-widget');
if (form && caja) {
  const estado = form.querySelector('[data-captcha-estado]');
  const boton = form.querySelector('button[type="submit"]');
  const decir = (t) => { if (estado) estado.textContent = t; };
  boton.disabled = true;
  new PowCaptchaClient(caja, {
    siteKey: caja.dataset.sitekey || null,
    apiBase: caja.dataset.api,
    onVerified() { boton.disabled = false; decir('Verificación humana superada: ya puede continuar.'); },
    onError(e) { boton.disabled = true; decir(`${e.message}. Pulse de nuevo «No soy un robot».`); },
  });
  form.addEventListener('submit', (ev) => {
    const token = form.querySelector('input[name="captcha_token"]');
    if (!token || !token.value) { ev.preventDefault(); ev.stopImmediatePropagation(); decir('Marque «No soy un robot» antes de continuar.'); }
  }, true);
}
