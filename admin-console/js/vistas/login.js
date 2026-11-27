// Acceso administrativo en dos pasos visuales: credenciales y código TOTP (6 u 8 dígitos)
// con casillas de avance automático, pegado del código completo y mensajes genéricos.
// Una sola petición POST /admin/api/login { usuario, password, codigo } al completar el paso 2.
import { h, $ } from '../dom.js';
import { icono } from '../iconos.js';
import { api, ErrorApi } from '../api.js';

let enlazado = false;
let opciones = { alEntrar: () => {}, esMock: false };
let digitos = 6;
let enviando = false;
let temporizadorEspera = null;

const MENSAJE_GENERICO = 'No se pudo iniciar sesión. Verifica tus credenciales y el código de verificación.';

function mostrarError(texto) {
  const el = $('#login-error');
  if (!texto) { el.hidden = true; el.replaceChildren(); return; }
  el.className = 'alerta alerta--peligro';
  el.replaceChildren(icono('error'), h('span', { text: texto }));
  el.hidden = false;
}

function irAPaso(n) {
  $('#form-credenciales').hidden = n !== 1;
  $('#form-codigo').hidden = n !== 2;
  for (const li of document.querySelectorAll('.paso')) {
    const p = Number(li.dataset.paso);
    li.classList.toggle('completado', p < n);
    if (p === n) li.setAttribute('aria-current', 'step');
    else li.removeAttribute('aria-current');
  }
  if (n === 1) $('#login-usuario').value ? $('#login-password').focus() : $('#login-usuario').focus();
  else casillas()[0]?.focus();
}

const casillas = () => [...document.querySelectorAll('#codigo-casillas input')];
const codigoActual = () => casillas().map((c) => c.value).join('');

function crearCasillas() {
  const cont = $('#codigo-casillas');
  cont.replaceChildren();
  cont.classList.toggle('codigo-casillas--8', digitos === 8);
  for (let i = 0; i < digitos; i++) {
    const input = h('input', {
      type: 'text', inputmode: 'numeric', pattern: '[0-9]*', maxlength: 1, autocomplete: i === 0 ? 'one-time-code' : 'off',
      'aria-label': `Dígito ${i + 1} de ${digitos}`, class: 'casilla', dataset: { i },
    });
    cont.append(input);
    if (digitos === 6 && i === 2) cont.append(h('span.casilla-separador', { 'aria-hidden': 'true' }));
    if (digitos === 8 && i === 3) cont.append(h('span.casilla-separador', { 'aria-hidden': 'true' }));
  }
  $('#codigo-leyenda').textContent = `Código de ${digitos} dígitos`;
  $('#login-cambiar-digitos').textContent = digitos === 6 ? 'Usar código de 8 dígitos' : 'Usar código de 6 dígitos';
}

function repartir(desde, texto) {
  const lista = casillas();
  const cifras = texto.replace(/\D/g, '').split('');
  let i = desde;
  for (const c of cifras) {
    if (i >= lista.length) break;
    lista[i].value = c;
    i++;
  }
  lista[Math.min(i, lista.length - 1)].focus();
  if (codigoActual().length === digitos) enviar();
}

function manejarCasillas() {
  const cont = $('#codigo-casillas');
  cont.addEventListener('input', (e) => {
    const input = /** @type {HTMLInputElement} */ (e.target);
    if (!input.matches('input')) return;
    const i = Number(input.dataset.i);
    const valor = input.value.replace(/\D/g, '');
    if (valor.length > 1) { input.value = ''; repartir(i, valor); return; }
    input.value = valor;
    mostrarError(null);
    if (valor && i < digitos - 1) casillas()[i + 1].focus();
    if (codigoActual().length === digitos) enviar();
  });
  cont.addEventListener('keydown', (e) => {
    const input = /** @type {HTMLInputElement} */ (e.target);
    if (!input.matches('input')) return;
    const i = Number(input.dataset.i);
    const lista = casillas();
    if (e.key === 'Backspace' && !input.value && i > 0) { lista[i - 1].value = ''; lista[i - 1].focus(); e.preventDefault(); }
    else if (e.key === 'ArrowLeft' && i > 0) { lista[i - 1].focus(); e.preventDefault(); }
    else if (e.key === 'ArrowRight' && i < lista.length - 1) { lista[i + 1].focus(); e.preventDefault(); }
    else if (e.key.length === 1 && !/[0-9]/.test(e.key) && !e.ctrlKey && !e.metaKey) e.preventDefault();
  });
  cont.addEventListener('paste', (e) => {
    const input = /** @type {HTMLInputElement} */ (e.target);
    const texto = e.clipboardData?.getData('text') ?? '';
    e.preventDefault();
    repartir(Number(input.dataset.i ?? 0), texto);
  });
  cont.addEventListener('focusin', (e) => { if (e.target.matches('input')) e.target.select(); });
}

function bloquearEnvio(segundos) {
  const boton = $('#login-entrar');
  clearInterval(temporizadorEspera);
  let restante = segundos;
  const pintar = () => {
    boton.disabled = true;
    boton.textContent = `Espera ${restante} s`;
    mostrarError(`Demasiados intentos. Podrás reintentar en ${restante} s.`);
  };
  pintar();
  temporizadorEspera = setInterval(() => {
    restante--;
    if (restante <= 0) {
      clearInterval(temporizadorEspera);
      boton.disabled = false;
      boton.textContent = 'Entrar';
      mostrarError(null);
      casillas()[0]?.focus();
    } else pintar();
  }, 1000);
}

async function enviar() {
  if (enviando || $('#login-entrar').disabled) return;
  const codigo = codigoActual();
  if (codigo.length !== digitos) {
    mostrarError(`Introduce los ${digitos} dígitos del código.`);
    casillas().find((c) => !c.value)?.focus();
    return;
  }
  enviando = true;
  const boton = $('#login-entrar');
  boton.disabled = true;
  boton.replaceChildren(h('span.spinner.spinner--claro', { 'aria-hidden': 'true' }), 'Verificando…');
  try {
    const sesion = await api.iniciarSesion($('#login-usuario').value.trim(), $('#login-password').value, codigo);
    $('#login-password').value = '';
    for (const c of casillas()) c.value = '';
    mostrarError(null);
    opciones.alEntrar(sesion);
  } catch (e) {
    for (const c of casillas()) c.value = '';
    if (e instanceof ErrorApi && e.status === 429) {
      enviando = false;
      bloquearEnvio(e.reintentarEn ?? 30);
      return;
    }
    if (e instanceof ErrorApi && e.status === 0) mostrarError('No hay conexión con el servicio. Comprueba la red e inténtalo de nuevo.');
    else if (e instanceof ErrorApi && e.status >= 500) mostrarError('El servicio no está disponible en este momento. Inténtalo más tarde.');
    else mostrarError(MENSAJE_GENERICO);
    casillas()[0]?.focus();
  } finally {
    enviando = false;
    if (!temporizadorEspera || boton.textContent === 'Verificando…') {
      boton.disabled = false;
      boton.textContent = 'Entrar';
    }
  }
}

function enlazar() {
  enlazado = true;
  const verBtn = $('#login-ver-password');
  verBtn.replaceChildren(icono('ojo'));
  verBtn.addEventListener('click', () => {
    const campo = $('#login-password');
    const visible = campo.type === 'text';
    campo.type = visible ? 'password' : 'text';
    verBtn.setAttribute('aria-pressed', String(!visible));
    verBtn.setAttribute('aria-label', visible ? 'Mostrar contraseña' : 'Ocultar contraseña');
    verBtn.replaceChildren(icono(visible ? 'ojo' : 'ojoNo'));
  });
  $('#login-password').addEventListener('keyup', (e) => {
    $('#login-bloq-mayus').hidden = !(e.getModifierState && e.getModifierState('CapsLock'));
  });
  $('#form-credenciales').addEventListener('submit', (e) => {
    e.preventDefault();
    const usuario = $('#login-usuario');
    const password = $('#login-password');
    for (const c of [usuario, password]) c.removeAttribute('aria-invalid');
    if (!usuario.value.trim() || !password.value) {
      mostrarError('Introduce tu usuario y tu contraseña.');
      const vacio = !usuario.value.trim() ? usuario : password;
      vacio.setAttribute('aria-invalid', 'true');
      vacio.focus();
      return;
    }
    mostrarError(null);
    $('#login-usuario-eco').textContent = usuario.value.trim();
    irAPaso(2);
  });
  $('#form-codigo').addEventListener('submit', (e) => { e.preventDefault(); enviar(); });
  $('#login-volver').addEventListener('click', () => { mostrarError(null); irAPaso(1); });
  $('#login-cambiar-digitos').addEventListener('click', () => {
    digitos = digitos === 6 ? 8 : 6;
    crearCasillas();
    casillas()[0].focus();
  });
  manejarCasillas();
  $('#login-pie-seguridad').prepend(icono('candado'));
}

/**
 * @param {{ mensaje?: string, esMock: boolean, alEntrar: (sesion: any) => void }} op
 */
export function montarLogin(op) {
  opciones = op;
  if (!enlazado) enlazar();
  digitos = 6;
  crearCasillas();
  irAPaso(1);
  const demo = $('#login-demo');
  demo.hidden = !op.esMock;
  if (op.esMock) {
    demo.replaceChildren(icono('info'), h('span', null,
      h('strong', { text: 'Modo demostración. ' }),
      'Usuario ', h('code', { text: 'admin' }), ', ', h('code', { text: 'operador' }), ' o ', h('code', { text: 'auditor' }),
      ', cualquier contraseña y cualquier código (', h('code', { text: '000000' }), ' simula un rechazo).'));
  }
  if (op.mensaje) {
    const el = $('#login-error');
    el.className = 'alerta alerta--info';
    el.replaceChildren(icono('info'), h('span', { text: op.mensaje }));
    el.hidden = false;
    const restaurar = () => { el.className = 'alerta alerta--peligro'; };
    $('#login-usuario').addEventListener('input', restaurar, { once: true });
  } else {
    mostrarError(null);
  }
}
