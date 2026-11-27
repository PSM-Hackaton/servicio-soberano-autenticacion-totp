// Punto de entrada del módulo de auditoría: bitácora encadenada y métricas operativas.

export {
  HASH_GENESIS, CLAVES_SENSIBLES, serializarCanonico, filtrarSensibles, calcularHash,
  crearBitacora, crearBitacoraSqlite, verificarCadena, respuestaVerificacion,
} from './cadena.js';
export { RESULTADOS_VERIFICACION, crearMetricas } from './metricas.js';
