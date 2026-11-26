// Arranque del servicio soberano TOTP.
// config → base de datos → repositorios → bóveda → firmas → detector → bitácora → métricas
// → casos de uso → servidor HTTPS. Tareas periódicas y apagado ordenado (SIGINT/SIGTERM).
// Los registros nunca incluyen secretos ni direcciones IP.

import { mkdirSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { cargarConfig, configCasosDeUso, CARPETA_BACKEND } from './infrastructure/config/config.js';
import { crearFirmas } from './infrastructure/config/firmas.js';
import { abrirBaseDatos } from './infrastructure/persistence/db.js';
import { crearRepositorios } from './infrastructure/persistence/repositorios.js';
import { crearVault } from './core/vault/vault.js';
import { crearBitacora, crearMetricas } from './audit/index.js';
import { entrenarDetectorPorDefecto } from './heuristics/index.js';
import { crearCasosDeUso, puede } from './application/use-cases/index.js';
import { crearServidor } from './api/servidor.js';
import { crearLimitador } from './security/index.js';

const CARPETA_REPO = resolve(CARPETA_BACKEND, '..');
const INTERVALO_SALUD_MS = 30_000;
const INTERVALO_PURGA_MS = 60 * 60_000;
const INTERVALO_RELOJ_MS = 10 * 60_000;
const DIAS_RETENCION_INTENTOS = 30;

/** Registro a consola con marca de tiempo. Quien llama es responsable de no pasar secretos. */
function crearRegistro(salida = console) {
  const linea = (nivel) => (mensaje) => salida[nivel === 'ERROR' ? 'error' : 'log'](`${new Date().toISOString()} ${nivel} ${mensaje}`);
  return { info: linea('INFO'), warn: linea('WARN'), error: linea('ERROR') };
}

/** Detector simulado para HEURISTICS_MODE=mock (desarrollo de clientes en paralelo). */
function detectorSimulado() {
  return {
    modo: 'mock',
    evaluar: () => ({ riskScore: 0, level: 'bajo', action: 'permitir', reasons: ['Detector simulado (modo mock)'], inferenceMs: 0 }),
  };
}

/** Mide el desfase de reloj contra una referencia local (cabecera Date), en ms. */
async function medirDesfase(url) {
  const t0 = Date.now();
  const r = await fetch(url, { method: 'HEAD', signal: AbortSignal.timeout(5000) });
  const t1 = Date.now();
  const fecha = Date.parse(r.headers.get('date') ?? '');
  if (!Number.isFinite(fecha)) throw new Error('La referencia no devolvió cabecera Date');
  return fecha - (t0 + t1) / 2;
}

/**
 * Construye y arranca el servicio.
 * @param {{ config?: ReturnType<typeof cargarConfig>, registro?: ReturnType<typeof crearRegistro>, senales?: boolean }} [opciones]
 */
export async function iniciar({ config = cargarConfig(), registro = crearRegistro(), senales = true } = {}) {
  // Base de datos
  if (config.baseDatos.ruta !== ':memory:') mkdirSync(dirname(config.baseDatos.ruta), { recursive: true });
  const db = abrirBaseDatos(config.baseDatos.ruta);
  const repos = crearRepositorios(db);
  registro.info('Base de datos SQLite abierta y migrada');

  // Bóveda y firmas
  const vault = crearVault(config.vault);
  const firmas = crearFirmas({ repos, vault }).recargar();
  registro.info(`Clave de firma activa: ${firmas.kidActivo}`);

  // Detector local de anomalías
  const inicioDetector = performance.now();
  const detector = config.heuristicas === 'mock'
    ? detectorSimulado()
    : entrenarDetectorPorDefecto(42, { modo: config.heuristicas === 'monitorizacion' ? 'monitorizacion' : 'bloqueo' });
  registro.info(`Detector de anomalías listo (modo ${detector.modo}, ${Math.round(performance.now() - inicioDetector)} ms)`);

  // Auditoría, métricas y casos de uso
  const bitacora = crearBitacora({ ultimo: () => repos.auditLog.ultimo(), insertar: (fila) => repos.auditLog.insertar(fila).id });
  const metricas = crearMetricas();
  const casos = crearCasosDeUso({
    repos, vault, firmas, detector, bitacora, metricas, config: configCasosDeUso(config), reloj: () => Date.now(), db,
  });

  const salud = () => {
    db.prepare('SELECT 1').get();
    return true;
  };

  // TLS
  let tls = null;
  if (config.tls.modo === 'node') {
    try {
      tls = { cert: readFileSync(/** @type {string} */ (config.tls.cert)), key: readFileSync(/** @type {string} */ (config.tls.key)) };
    } catch {
      db.close();
      throw new Error(`No se pudieron leer el certificado o la llave TLS (${config.tls.cert}). Ejecute "npm run certs".`);
    }
  }

  const servidor = crearServidor({
    casos,
    metricas,
    puede,
    cors: { origenes: [...config.corsOrigenes] },
    limitadores: {
      global: crearLimitador({ capacidad: config.limites.globalPorMin, ventanaMs: 60_000 }),
      porApp: crearLimitador({ capacidad: config.limites.appPorMin, ventanaMs: 60_000 }),
      porOrigen: crearLimitador({ capacidad: config.limites.origenPorMin, ventanaMs: 60_000 }),
    },
    salud,
    info: () => ({
      dbDriver: 'sqlite',
      activeKeyId: firmas.kidActivo ?? '',
      heuristicsMode: config.heuristicas,
    }),
    tls,
    registro,
    estaticos: [
      { prefijo: '/app', carpeta: resolve(CARPETA_REPO, 'authenticator-app') },
      { prefijo: '/consola', carpeta: resolve(CARPETA_REPO, 'admin-console') },
    ],
  });

  await new Promise((resolver, rechazar) => {
    servidor.once('error', rechazar);
    servidor.listen(config.puerto, config.host, () => {
      servidor.off('error', rechazar);
      resolver(undefined);
    });
  });
  const direccion = servidor.address();
  const puerto = typeof direccion === 'object' && direccion ? direccion.port : config.puerto;
  registro.info(`Servicio escuchando en ${tls ? 'https' : 'http'}://${config.host}:${puerto} (${servidor.api.rutas.length} rutas API)`);
  if (!tls) registro.warn('TLS_MODE=off: solo para pruebas locales');

  // Tareas periódicas
  const temporizadores = [];
  const cada = (ms, fn) => {
    const t = setInterval(() => {
      Promise.resolve().then(fn).catch((e) => registro.warn(`Tarea periódica fallida: ${e?.message ?? e}`));
    }, ms);
    t.unref();
    temporizadores.push(t);
  };

  cada(INTERVALO_SALUD_MS, () => {
    try {
      salud();
      metricas.registrarChequeoSalud(true);
    } catch (e) {
      metricas.registrarChequeoSalud(false);
      metricas.registrarErrorBaseDatos();
      registro.error(`Chequeo de salud fallido: ${e?.message ?? e}`);
    }
  });

  const purgar = () => {
    const intentos = repos.attempts.purgarAntiguos(DIAS_RETENCION_INTENTOS);
    const jti = repos.consumedJti.purgarCaducados();
    if (intentos || jti) registro.info(`Purga: ${intentos} intentos antiguos y ${jti} jti caducados`);
  };
  purgar();
  cada(INTERVALO_PURGA_MS, purgar);

  if (config.referenciaReloj) {
    const medir = async () => {
      const ms = await medirDesfase(config.referenciaReloj);
      metricas.fijarDesfaseReloj(ms);
      if (Math.abs(ms) > 5000) registro.warn(`Desfase de reloj elevado: ${Math.round(ms)} ms`);
    };
    medir().catch((e) => registro.warn(`No se pudo medir el desfase de reloj: ${e?.message ?? e}`));
    cada(INTERVALO_RELOJ_MS, medir);
  }

  // Apagado ordenado
  let apagando = false;
  async function detener(motivo = 'solicitud') {
    if (apagando) return;
    apagando = true;
    registro.info(`Apagando servicio (${motivo})`);
    for (const t of temporizadores) clearInterval(t);
    const forzar = setTimeout(() => servidor.closeAllConnections(), 5000);
    forzar.unref();
    servidor.closeIdleConnections();
    await new Promise((r) => servidor.close(() => r(undefined)));
    clearTimeout(forzar);
    try {
      db.close();
    } catch { /* ya cerrada */ }
    registro.info('Servicio detenido');
  }

  if (senales) {
    for (const senal of ['SIGINT', 'SIGTERM']) {
      process.once(senal, () => {
        const salidaForzada = setTimeout(() => process.exit(1), 10_000);
        salidaForzada.unref();
        detener(senal).then(() => process.exit(0), () => process.exit(1));
      });
    }
  }

  return { servidor, db, repos, casos, firmas, metricas, puerto, detener };
}

// Ejecución directa: node src/main.js
const esPrincipal = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (esPrincipal) {
  const registro = crearRegistro();
  iniciar({ registro }).catch((e) => {
    registro.error(e?.message ?? String(e));
    process.exit(1);
  });
}
