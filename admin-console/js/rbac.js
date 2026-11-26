// Control de acceso por rol en la interfaz. Es solo una ayuda de usabilidad: el servidor
// impone los mismos permisos y responde 403 ante cualquier intento fuera de rol.

export const ROLES = Object.freeze(['Administrador', 'Operador', 'Auditor']);

/** Matriz de permisos (acción → roles autorizados). */
// Alineada con backend/src/application/use-cases/rbac.js (MATRIZ_RBAC).
export const PERMISOS = Object.freeze({
  'panel.ver': ['Administrador', 'Operador', 'Auditor'], // metricas.leer
  'apps.ver': ['Administrador', 'Operador'], // apps.leer
  'apps.editar': ['Administrador', 'Operador'], // apps.escribir (también registra apps nuevas)
  'apps.secreto': ['Administrador'], // apps.secreto (regenerar client_secret)
  'enrolamientos.ver': ['Administrador', 'Operador'], // enrolamientos.leer (incluye la búsqueda por cédula)
  'enrolamientos.suspender': ['Administrador', 'Operador'], // enrolamientos.gestionar
  'enrolamientos.revocar': ['Administrador', 'Operador'], // enrolamientos.gestionar
  'anomalias.ver': ['Administrador', 'Operador', 'Auditor'], // anomalias.leer
  'llaves.ver': ['Administrador', 'Operador', 'Auditor'], // llaves.leer (GET /admin/api/keys)
  'llaves.rotar': ['Administrador'], // llaves.rotar
  'auditoria.ver': ['Administrador', 'Auditor'], // auditoria.leer
  'auditoria.verificar': ['Administrador', 'Auditor'], // auditoria.verificar
  'admins.ver': ['Administrador'], // admins.leer
  'admins.editar': ['Administrador'], // admins.escribir (crear y deshabilitar cuentas)
});

/** Descripción breve de cada rol para la interfaz. */
export const DESCRIPCION_ROL = Object.freeze({
  Administrador: 'Gestiona políticas, llaves, enrolamientos y cuentas de la consola.',
  Operador: 'Supervisa la operación, atiende el soporte de enrolamientos y ajusta las políticas de las aplicaciones.',
  Auditor: 'Consulta el detector y verifica la bitácora; solo lectura.',
});

/** @param {string | undefined} rol @param {keyof typeof PERMISOS} permiso */
export function puede(rol, permiso) {
  return Boolean(rol && PERMISOS[permiso]?.includes(rol));
}

/** Texto para explicar por qué una acción está deshabilitada. */
export function motivoSinPermiso(permiso) {
  const roles = PERMISOS[permiso] ?? [];
  return roles.length ? `Disponible para: ${roles.join(', ')}` : 'Acción no disponible';
}
