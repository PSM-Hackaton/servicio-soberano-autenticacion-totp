// Página pública de estado del servicio (/estado, Issue #52 · F5).
// Consulta /health/ready y /health cada 30 s, sin exponer datos sensibles ni métricas internas.

import './sitio.js';

const INTERVALO_MS = 30_000;

async function consultarEstado() {
  const banner = document.getElementById('estado-banner');
  const valorSalud = document.getElementById('valor-salud');
  const valorHora = document.getElementById('valor-hora');
  const valorDesfase = document.getElementById('valor-desfase');
  const valorActualizado = document.getElementById('valor-actualizado');
  if (!banner) return;

  const t0 = Date.now();
  try {
    const res = await fetch('/health/ready', { cache: 'no-store' });
    const t1 = Date.now();
    const datos = await res.json().catch(() => null);

    if (!res.ok) {
      banner.textContent = 'Servicio no disponible temporalmente';
      banner.className = 'estado-caja estado-error';
      valorSalud.textContent = `No disponible (HTTP ${res.status})`;
      valorHora.textContent = '—';
      valorDesfase.textContent = '—';
    } else {
      const fechaServidor = datos?.timestamp || res.headers.get('date');
      const servidorMs = fechaServidor ? Date.parse(fechaServidor) : NaN;
      const desfaseMs = Number.isFinite(servidorMs) ? Math.round(servidorMs - (t0 + t1) / 2) : null;

      banner.textContent = 'Servicio operativo';
      banner.className = 'estado-caja estado-ok';
      valorSalud.textContent = 'Operativo (base de datos y firma listas)';
      valorHora.textContent = fechaServidor || new Date().toISOString();
      valorDesfase.textContent = desfaseMs === null
        ? 'No disponible'
        : `${desfaseMs >= 0 ? '+' : ''}${desfaseMs} ms${Math.abs(desfaseMs) > 15_000 ? ' (aviso: revisa la hora de tu dispositivo)' : ' (sincronizado)'}`;
    }
  } catch {
    banner.textContent = 'Servicio no disponible';
    banner.className = 'estado-caja estado-error';
    valorSalud.textContent = 'Sin respuesta de red';
    valorHora.textContent = '—';
    valorDesfase.textContent = '—';
  }
  valorActualizado.textContent = new Date().toLocaleTimeString('es-VE');
}

document.getElementById('btn-refrescar')?.addEventListener('click', consultarEstado);
consultarEstado();
setInterval(consultarEstado, INTERVALO_MS);
