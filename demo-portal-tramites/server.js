#!/usr/bin/env node
// Arranque del Portal de Trámites del Estado (demo institucional).
//   node server.js            usa demo-portal-tramites/.env
// HTTPS si existen los certificados configurados (por defecto ../backend/certs/); si no, HTTP en localhost.

import { configuracion } from './src/config.js';
import { crearPortal } from './src/portal.js';

let config;
try {
  config = configuracion();
} catch (e) {
  process.stderr.write(`${e.message}\n`);
  process.exit(1);
}
const esLocal = ['127.0.0.1', 'localhost', '::1'].includes(config.host);
if (!config.tls && !esLocal) {
  process.stderr.write('Sin certificados TLS el portal solo puede escuchar en localhost (PORTAL_HOST=127.0.0.1).\n');
  process.exit(1);
}
if (!config.servicio.clientSecret) {
  process.stderr.write('Aviso: TOTP_CLIENT_SECRET vacío en .env; las llamadas al servicio serán rechazadas.\n');
}

const portal = await crearPortal({ config, registrar: (m) => process.stderr.write(`[portal] ${m}\n`) });
const url = await portal.iniciar();
process.stdout.write(
  `Portal de Trámites del Estado en ${url} (${portal.tls ? 'HTTPS' : 'HTTP solo local, sin certificados'})\n`
  + `  Servicio TOTP: ${config.servicio.baseUrl} · client_id ${config.servicio.clientId}\n`
  + `  Usuarios demo: ${config.archivoUsuarios}\n`,
);

const salir = async () => { await portal.detener(); process.exit(0); };
process.on('SIGINT', salir);
process.on('SIGTERM', salir);
