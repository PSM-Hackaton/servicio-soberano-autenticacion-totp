// Rotación de la llave maestra AES-256-GCM. Pasos previos en el .env (o ENV_FILE):
//   1. Añadir MASTER_KEY_V2_HEX (64 hex del CSPRNG) y poner MASTER_KEY_VERSION=v2.
//   2. Conservar MASTER_KEY_V1_HEX mientras queden datos cifrados con v1.
// Este script recifra en una transacción todas las semillas y claves privadas de firma que no
// estén en la versión activa e informa los conteos. Es idempotente: una segunda ejecución no
// cambia nada. Tras comprobarlo (y con copia de seguridad) ya se puede retirar la llave anterior.
// Uso: npm run rotar-llave-maestra   (con el servicio detenido)

import { existsSync } from 'node:fs';

import { cargarConfig } from '../src/infrastructure/config/config.js';
import { abrirBaseDatos } from '../src/infrastructure/persistence/db.js';
import { crearRepositorios } from '../src/infrastructure/persistence/repositorios.js';
import { recifrarConLlaveActiva } from '../src/infrastructure/persistence/rotacionLlaveMaestra.js';
import { crearBitacora } from '../src/audit/index.js';
import { crearVault } from '../src/core/vault/vault.js';

const config = cargarConfig();
if (config.baseDatos.ruta === ':memory:' || !existsSync(config.baseDatos.ruta)) {
  console.error(`No existe la base de datos ${config.baseDatos.ruta}: no hay datos que rotar.`);
  process.exit(1);
}
const db = abrirBaseDatos(config.baseDatos.ruta);
try {
  const repos = crearRepositorios(db);
  const vault = crearVault(config.vault);
  const bitacora = crearBitacora({ ultimo: () => repos.auditLog.ultimo(), insertar: (f) => repos.auditLog.insertar(f).id });
  const r = recifrarConLlaveActiva({ repos, vault, bitacora });
  console.log(`Versión activa de la llave maestra: ${r.versionActiva}`);
  console.log(`  Semillas recifradas:                 ${r.semillas}`);
  console.log(`  Claves privadas de firma recifradas: ${r.clavesFirma}`);
  console.log(`  Secretos de derivación de cédula:    ${r.secretosCedula}`);
  if (r.semillas + r.clavesFirma + r.secretosCedula === 0) console.log('  Nada que rotar: todo el material ya usa la versión activa.');
} catch (e) {
  console.error(`Rotación abortada (no se modificó nada): ${e?.message ?? e}`);
  process.exitCode = 1;
} finally {
  db.close();
}
