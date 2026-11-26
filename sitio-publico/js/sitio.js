// Utilidades comunes del sitio público (cambio de tema accesible sin inline JS).

const CLAVE_TEMA = 'totp_sitio_tema';

export function iniciarTema() {
  const guardado = localStorage.getItem(CLAVE_TEMA);
  if (guardado === 'claro' || guardado === 'oscuro') {
    document.documentElement.setAttribute('data-tema', guardado);
  }
  const btn = document.getElementById('btn-tema');
  if (!btn) return;
  const actualizarEtiqueta = () => {
    const actual = document.documentElement.getAttribute('data-tema');
    const esOscuro = actual === 'oscuro' || (!actual && window.matchMedia('(prefers-color-scheme: dark)').matches);
    btn.textContent = esOscuro ? 'Modo claro' : 'Modo oscuro';
    btn.setAttribute('aria-pressed', String(esOscuro));
  };
  actualizarEtiqueta();
  btn.addEventListener('click', () => {
    const actual = document.documentElement.getAttribute('data-tema');
    const esOscuro = actual === 'oscuro' || (!actual && window.matchMedia('(prefers-color-scheme: dark)').matches);
    const siguiente = esOscuro ? 'claro' : 'oscuro';
    document.documentElement.setAttribute('data-tema', siguiente);
    localStorage.setItem(CLAVE_TEMA, siguiente);
    actualizarEtiqueta();
  });
}

iniciarTema();
