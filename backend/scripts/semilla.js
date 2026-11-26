// Datos semilla: apps "Portal de Trámites" y "Reto 1" (client_id + client_secret mostrados UNA vez)
// y administrador inicial con contraseña aleatoria y enrolamiento TOTP activo (URI otpauth + QR SVG
// en backend/data/admin-qr.svg). Idempotente: lo que ya existe no se toca ni se vuelve a mostrar.
// Uso: node scripts/semilla.js   (lee backend/.env o ENV_FILE)

import { randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { cargarConfig, configCasosDeUso } from '../src/infrastructure/config/config.js';
import { crearFirmas } from '../src/infrastructure/config/firmas.js';
import { abrirBaseDatos } from '../src/infrastructure/persistence/db.js';
import { crearRepositorios } from '../src/infrastructure/persistence/repositorios.js';
import { crearVault } from '../src/core/vault/vault.js';
import { generateTotp } from '../src/core/totp/totp.js';
import { base32Decode } from '../src/core/totp/base32.js';
import { crearBitacora, crearMetricas } from '../src/audit/index.js';
import { hashSecretoAsync } from '../src/security/index.js';
import { crearCasosDeUso } from '../src/application/use-cases/index.js';

const CARPETA_BACKEND = fileURLToPath(new URL('../', import.meta.url));
const RUTA_QR = resolve(CARPETA_BACKEND, 'data', 'admin-qr.svg');
const APPS_INTEGRADORAS = ['Portal de Trámites', 'Reto 1'];
const APP_CONSOLA = 'Consola Administrativa';
const ACTOR_SEMILLA = Object.freeze({ id: 'semilla', usuario: 'semilla', rol: 'Administrador' });

const config = cargarConfig();
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
    // App interna que aloja el factor TOTP de la consola (su secreto se descarta: no integra a nadie).
    const { app: consola } = await asegurarApp(APP_CONSOLA);
    const ctxApp = { app: consola, ip: '127.0.0.1' };
    const enrol = await casos.enrolar({ user_ref: `admin:${usuario}`, account_label: usuario }, ctxApp);
    if (enrol.status !== 201) throw new Error(`No se pudo crear el enrolamiento del admin (HTTP ${enrol.status})`);
    const { enrollment_id: enrollmentId, otpauth_uri: uri, qr_svg: qr, algoritmo, digitos, periodo } = enrol.cuerpo;

    // Activación con el código actual derivado de la propia URI (la semilla no se guarda en ningún sitio).
    const semilla = base32Decode(new URL(uri).searchParams.get('secret') ?? '');
    const codigo = generateTotp(semilla, Date.now(), { algoritmo, digitos, periodo });
    semilla.fill(0);
    const act = await casos.activar({ id: enrollmentId, cuerpo: { code: codigo } }, ctxApp);
    if (act.status !== 200) throw new Error(`No se pudo activar el TOTP del admin (HTTP ${act.status})`);

    const password = randomBytes(18).toString('base64url');
    const admin = repos.admins.crear({
      usuario, password_hash: await hashSecretoAsync(password), rol: 'Administrador', totp_enrollment_id: enrollmentId,
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
    for (const c of act.cuerpo.recovery_codes ?? []) console.log(`    ${c}`);
    console.log('  Nota: el código del paso actual ya se consumió al activar; espere al siguiente para iniciar sesión.');
  }
  console.log(linea);
} catch (e) {
  console.error(`Error en la semilla: ${e?.message ?? e}`);
  process.exitCode = 1;
} finally {
  db.close();
}
