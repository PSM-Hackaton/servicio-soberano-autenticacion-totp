// Banco de pruebas de capacidad: arranca el MISMO servicio que backend/src/main.js (mismos módulos,
// mismo orden de ensamblado, TLS 1.3, SQLite WAL, detector local, bitácora encadenada) con solo
// dos diferencias, ambas documentadas en docs/escalabilidad/escalabilidad.html (anexo):
//   1. Límites de tasa muy altos, para medir la capacidad del servicio y no la del limitador.
//   2. Reloj acelerado ACELERACION veces (reloj = T0 + (ahora - T0) * K). Así cada usuario de prueba
//      puede autenticarse varias veces por segundo sin chocar con la protección anti replay (un código
//      por usuario y paso de 30 s). El trabajo por petición (HMAC, AES-GCM, Ed25519, SQLite) es idéntico.
// No modifica el producto. Uso: ENV_FILE=... T0=<epoch ms> ACELERACION=100 node banco.js <carpeta-salida>

import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const BACKEND = fileURLToPath(new URL('../../../backend/src/', import.meta.url));
const m = (ruta) => import(resolve(BACKEND, ruta));

const { cargarConfig, configCasosDeUso } = await m('infrastructure/config/config.js');
const { crearFirmas } = await m('infrastructure/config/firmas.js');
const { abrirBaseDatos } = await m('infrastructure/persistence/db.js');
const { crearRepositorios } = await m('infrastructure/persistence/repositorios.js');
const { crearVault } = await m('core/vault/vault.js');
const { crearBitacora, crearMetricas } = await m('audit/index.js');
const { entrenarDetectorPorDefecto } = await m('heuristics/index.js');
const { crearCasosDeUso, puede } = await m('application/use-cases/index.js');
const { crearServidor } = await m('api/servidor.js');
const { crearLimitador } = await m('security/index.js');

const salida = process.argv[2];
const T0 = Number(process.env.T0);
const K = Number(process.env.ACELERACION ?? 1);
if (!salida || !Number.isFinite(T0) || !(K >= 1)) throw new Error('Uso: T0=<ms> ACELERACION=<k> node banco.js <carpeta>');
const reloj = () => T0 + (Date.now() - T0) * K;

const config = cargarConfig();
const db = abrirBaseDatos(config.baseDatos.ruta);
// Variante de afinado (etapa 2): SINCRONO=NORMAL evita un fsync por transacción en modo WAL.
// Sin la variable se usa el valor por defecto de SQLite que hoy usa el producto (FULL).
if (process.env.SINCRONO) db.exec(`PRAGMA synchronous = ${process.env.SINCRONO === 'NORMAL' ? 'NORMAL' : 'FULL'};`);
const sincrono = ['OFF', 'NORMAL', 'FULL', 'EXTRA'][db.prepare('PRAGMA synchronous').get().synchronous];
const repos = crearRepositorios(db);
const vault = crearVault(config.vault);
const firmas = crearFirmas({ repos, vault }).recargar();
const detector = entrenarDetectorPorDefecto(42, { modo: config.heuristicas === 'monitorizacion' ? 'monitorizacion' : 'bloqueo' });
const bitacora = crearBitacora({ ultimo: () => repos.auditLog.ultimo(), insertar: (f) => repos.auditLog.insertar(f).id });
const metricas = crearMetricas();
const casos = crearCasosDeUso({ repos, vault, firmas, detector, bitacora, metricas, config: configCasosDeUso(config), reloj, db });

// App integradora de prueba (como la registra la consola o la semilla).
const admin = { admin: { id: 'banco', usuario: 'banco', rol: 'Administrador' }, ip: '127.0.0.1' };
const r = await casos.adminActualizarApp({ nombre: `Banco ${Date.now()}` }, admin);
if (r.status !== 201) throw new Error(`No se pudo registrar la app (${r.status})`);

const alto = () => crearLimitador({ capacidad: 10_000_000, ventanaMs: 60_000 });
const servidor = crearServidor({
  casos, metricas, puede,
  limitadores: { global: alto(), porApp: alto(), porOrigen: alto() },
  tls: { cert: readFileSync(config.tls.cert), key: readFileSync(config.tls.key) },
  registro: { info() {}, warn() {}, error: (t) => console.error(t) },
  info: () => ({ dbDriver: 'sqlite', activeKeyId: firmas.kidActivo ?? '', heuristicsMode: config.heuristicas }),
});
servidor.listen(config.puerto, '127.0.0.1', () => {
  writeFileSync(resolve(salida, 'banco.json'), JSON.stringify({
    pid: process.pid, puerto: config.puerto, client_id: r.cuerpo.client_id, client_secret: r.cuerpo.client_secret,
    db: config.baseDatos.ruta, T0, K, heuristicas: config.heuristicas, sincrono,
  }), { mode: 0o600 });
  console.log(`LISTO pid=${process.pid} puerto=${config.puerto} K=${K}`);
});
const parar = () => servidor.close(() => { db.close(); process.exit(0); });
process.once('SIGTERM', parar);
process.once('SIGINT', parar);
