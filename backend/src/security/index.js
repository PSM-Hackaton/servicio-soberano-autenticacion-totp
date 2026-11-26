// Punto de entrada del módulo de seguridad (lógica pura, sin servidor HTTP).

export {
  hashSecreto, verificarSecreto, hashSecretoAsync, verificarSecretoAsync,
  generarSecretoCliente, generarClientId, PARAMETROS_SCRYPT,
} from './secretos.js';
export { generarCodigosRecuperacion, normalizarCodigoRecuperacion, ALFABETO_RECUPERACION } from './recuperacion.js';
export { calcularBloqueo, bloqueadoHasta, estaBloqueado, ESCALONES_BLOQUEO } from './bloqueo.js';
export { crearLimitador } from './limitador.js';
export { validarCuerpo } from './validacion.js';
export { cabecerasSeguridad, politicaPermisos, politicaPermisosPara } from './cabeceras.js';
export { errorGenerico } from './errores.js';
export { normalizarIp, esIpValida } from './ip.js';
