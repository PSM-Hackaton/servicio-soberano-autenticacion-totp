// Punto de entrada del detector local de anomalías (Isolation Forest + reglas explicables).

export { crearAleatorio, semillaANumero } from './aleatorio.js';
export {
  extraerCaracteristicas, describirCaracteristicas, recorrerFlujo, aMs,
  NOMBRES_CARACTERISTICAS, DIMENSION, VENTANA_MS, HORA_PATRON_POR_DEFECTO,
} from './caracteristicas.js';
export { entrenar, puntuar, serializar, deserializar, c } from './isolationForest.js';
export {
  generarTraficoNormal, generarAtaque, generarTraficoMixto, hashCuenta, hashIp, TIPOS_ATAQUE, INICIO_POR_DEFECTO,
} from './generadorTrafico.js';
export {
  crearDetector, entrenarModelo, entrenarDetectorPorDefecto, vectorizarFlujo, serializarModelo, deserializarModelo,
  aRiesgoContrato, REGLAS_POR_DEFECTO, UMBRALES_POR_DEFECTO,
} from './detector.js';
