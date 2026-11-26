// Control de acceso por rol (RBAC) de la consola administrativa.

/** Acciones administrativas reconocidas. */
// llaves.leer: inventario de claves de firma (solo kid, estado y fechas; nunca material privado).
// enrolamientos.gestionar: suspender, reactivar y revocar enrolamientos desde la consola.
// apps.secreto: regenerar el client_secret de una app (invalida el anterior).
// admins.leer / admins.escribir: cuentas de la consola (listar; crear y deshabilitar).
export const ACCIONES = Object.freeze([
  'apps.leer', 'apps.escribir', 'apps.secreto', 'enrolamientos.leer', 'enrolamientos.gestionar', 'llaves.leer', 'llaves.rotar',
  'auditoria.leer', 'auditoria.verificar', 'anomalias.leer', 'metricas.leer', 'admins.leer', 'admins.escribir',
]);

/** Matriz rol → acciones permitidas. */
export const MATRIZ_RBAC = Object.freeze({
  Administrador: Object.freeze([...ACCIONES]),
  Operador: Object.freeze(['apps.leer', 'apps.escribir', 'enrolamientos.leer', 'enrolamientos.gestionar', 'llaves.leer',
    'anomalias.leer', 'metricas.leer']),
  Auditor: Object.freeze(['auditoria.leer', 'auditoria.verificar', 'llaves.leer', 'anomalias.leer', 'metricas.leer']),
});

/**
 * Indica si un rol puede ejecutar una acción. Rol o acción desconocidos → false.
 * @param {string} rol @param {string} accion
 * @returns {boolean}
 */
export function puede(rol, accion) {
  return Object.hasOwn(MATRIZ_RBAC, rol) && MATRIZ_RBAC[rol].includes(accion);
}
