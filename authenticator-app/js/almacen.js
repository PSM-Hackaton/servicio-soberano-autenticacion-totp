// Envoltorio mínimo de IndexedDB (clave → valor). Aquí solo se guardan datos cifrados
// (la bóveda) y datos no sensibles (contador de intentos, preferencias).

const NOMBRE_BD = 'autenticador-soberano';
const ALMACEN = 'kv';

/** @type {Promise<IDBDatabase> | null} */
let conexion = null;

function abrir() {
  if (conexion) return conexion;
  conexion = new Promise((resolver, rechazar) => {
    const peticion = indexedDB.open(NOMBRE_BD, 1);
    peticion.onupgradeneeded = () => peticion.result.createObjectStore(ALMACEN);
    peticion.onsuccess = () => {
      const bd = peticion.result;
      bd.onversionchange = () => { bd.close(); conexion = null; };
      resolver(bd);
    };
    peticion.onerror = () => { conexion = null; rechazar(peticion.error); };
  });
  return conexion;
}

async function operar(modo, accion) {
  const bd = await abrir();
  return new Promise((resolver, rechazar) => {
    const tx = bd.transaction(ALMACEN, modo);
    const peticion = accion(tx.objectStore(ALMACEN));
    tx.oncomplete = () => resolver(peticion?.result);
    tx.onerror = () => rechazar(tx.error);
    tx.onabort = () => rechazar(tx.error);
  });
}

/** @param {string} clave */
export function leer(clave) {
  return operar('readonly', (s) => s.get(clave));
}

/** @param {string} clave @param {unknown} valor */
export function escribir(clave, valor) {
  return operar('readwrite', (s) => s.put(valor, clave));
}

/** Elimina la base de datos completa. */
export async function eliminarTodo() {
  if (conexion) {
    (await conexion).close();
    conexion = null;
  }
  await new Promise((resolver, rechazar) => {
    const peticion = indexedDB.deleteDatabase(NOMBRE_BD);
    peticion.onsuccess = () => resolver();
    peticion.onerror = () => rechazar(peticion.error);
    peticion.onblocked = () => resolver();
  });
}
