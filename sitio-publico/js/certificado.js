// Calcula y muestra la huella SHA-256 real del certificado descargado desde GET /ca.crt (sin inline JS).

import './sitio.js';

async function calcularHuellaCa() {
  const el = document.getElementById('huella-sha256');
  const estado = document.getElementById('estado-ca');
  if (!el || !estado) return;

  try {
    const res = await fetch('/ca.crt', { cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const pem = await res.text();
    const b64 = pem
      .replace(/-----BEGIN CERTIFICATE-----/g, '')
      .replace(/-----END CERTIFICATE-----/g, '')
      .replace(/\s+/g, '');
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
    const hex = Array.from(digest, (b) => b.toString(16).padStart(2, '0').toUpperCase()).join(':');
    el.textContent = hex;
    estado.textContent = 'Certificado público disponible para descarga directa en /ca.crt.';
    estado.className = 'estado-caja estado-ok';
  } catch {
    el.textContent = 'Disponible cuando el servidor tenga configurada TLS_CA_PUBLIC_PATH (/ca.crt).';
    estado.textContent = 'No se pudo obtener /ca.crt automáticamente en este entorno.';
    estado.className = 'estado-caja estado-aviso';
  }
}

calcularHuellaCa();
