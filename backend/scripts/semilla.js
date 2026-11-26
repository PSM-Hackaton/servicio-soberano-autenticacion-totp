// Datos semilla: apps "Portal de Trámites" y "Agente Evaluador (Reto 3)" (client_id + client_secret mostrados UNA vez)
// y administrador inicial con contraseña aleatoria y enrolamiento TOTP activo (URI otpauth + QR SVG
// en ADMIN_QR_PATH o, por defecto, admin-qr.svg junto a SQLITE_DB_PATH). Idempotente: lo que ya existe no se toca ni se vuelve a mostrar.
// Uso: node scripts/semilla.js   (lee backend/.env o ENV_FILE)

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

import { cargarConfig, configCasosDeUso } from '../src/infrastructure/config/config.js';
import { crearFirmas } from '../src/infrastructure/config/firmas.js';
import { abrirBaseDatos } from '../src/infrastructure/persistence/db.js';
import { crearRepositorios } from '../src/infrastructure/persistence/repositorios.js';
import { crearVault } from '../src/core/vault/vault.js';
import { crearBitacora, crearMetricas } from '../src/audit/index.js';
import { crearCasosDeUso } from '../src/application/use-cases/index.js';
import { provisionarAdministrador } from '../src/application/use-cases/administradores.js';

const APPS_INTEGRADORAS = ['Portal de Trámites', 'Agente Evaluador (Reto 3)'];
const ACTOR_SEMILLA = Object.freeze({ id: 'semilla', usuario: 'semilla', rol: 'Administrador' });

const config = cargarConfig();
const RUTA_QR = config.admin.rutaQr;
if (config.baseDatos.ruta !== ':memory:') mkdirSync(dirname(config.baseDatos.ruta), { recursive: true });
const db = abrirBaseDatos(config.baseDatos.ruta);
const repos = crearRepositorios(db);
const vault = crearVault(config.vault);
const firmas = crearFirmas({ repos, vault }).recargar();
const bitacora = crearBitacora({ ultimo: () => repos.auditLog.ultimo(), insertar: (f) => repos.auditLog.insertar(f).id });
const detector = { evaluar: () => ({ riskScore: 0, level: 'bajo', action: 'permitir', reasons: ['semilla'], inferenceMs: 0 }) };
const casos = crearCasosDeUso({
  repos, vault, firmas, detector, bitacora, metricas: crearMetricas(), config: configCasosDeUso(config), reloj: () => Date.now(), db,
});
const ctxSemilla = { admin: ACTOR_SEMILLA, ip: '127.0.0.1' };

/** Crea la app si no existe otra con el mismo nombre. @returns {Promise<{ app: any, secreto: string | null }>} */
async function asegurarApp(nombre) {
  const existente = repos.apps.listar().find((a) => a.nombre === nombre);
  if (existente) return { app: existente, secreto: null };
  const r = await casos.adminActualizarApp({ nombre }, ctxSemilla);
  if (r.status !== 201) throw new Error(`No se pudo registrar la app ${nombre} (HTTP ${r.status})`);
  return { app: repos.apps.buscarPorId(r.cuerpo.app.id), secreto: r.cuerpo.client_secret };
}

const linea = '-'.repeat(72);
try {
  console.log(linea);
  console.log('Apps integradoras (el client_secret se muestra UNA sola vez; guárdelo ahora):');
  for (const nombre of APPS_INTEGRADORAS) {
    const { app, secreto } = await asegurarApp(nombre);
    console.log(`\n  ${nombre}`);
    console.log(`    client_id:     ${app.client_id}`);
    console.log(secreto ? `    client_secret: ${secreto}` : '    client_secret: (ya existía; no se puede recuperar)');
  }

  console.log(`\n${linea}`);
  const usuario = config.admin.usuarioSemilla;
  if (repos.admins.buscarPorUsuario(usuario)) {
    console.log(`El administrador "${usuario}" ya existe: no se modifica.`);
  } else {
    // Misma lógica que POST /admin/api/admins: contraseña aleatoria y TOTP propio ya activo en la
    // app interna "Consola Administrativa" (src/application/use-cases/administradores.js).
    const { admin, password, otpauthUri: uri, qrSvg: qr, codigosRecuperacion } = await provisionarAdministrador({
      repos, casos, usuario, rol: 'Administrador', ctxAdmin: ctxSemilla,
    });
    bitacora.registrar({ actor: 'admin:semilla', accion: 'admin.creado', objetivo: admin.id, detalle: { usuario, rol: 'Administrador' } });

    mkdirSync(dirname(RUTA_QR), { recursive: true });
    writeFileSync(RUTA_QR, qr, { mode: 0o600 });

    console.log('Administrador inicial (los datos se muestran UNA sola vez):');
    console.log(`  usuario:    ${usuario}`);
    console.log(`  contraseña: ${password}`);
    console.log(`  rol:        Administrador`);
    console.log(`  URI TOTP:   ${uri}`);
    console.log(`  QR SVG:     ${RUTA_QR} (escanéelo con la app autenticadora y luego bórrelo)`);
    console.log('  Códigos de recuperación:');
    for (const c of codigosRecuperacion) console.log(`    ${c}`);
    console.log('  Nota: el código del paso actual ya se consumió al activar; espere al siguiente para iniciar sesión.');
  }
  console.log(linea);
} catch (e) {
  console.error(`Error en la semilla: ${e?.message ?? e}`);
  process.exitCode = 1;
} finally {
  db.close();
}
