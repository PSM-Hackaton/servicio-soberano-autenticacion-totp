// Atajos sobre la API del servicio TOTP (contracts/openapi.yaml) y lectura de /metrics.

/**
 * POST /api/v1/verify. `op.clientIp` añade `client_ip` (IP del usuario final que enviaría un portal
 * integrador); sin él, el servicio usa la IP TCP de la conexión como origen.
 */
export function verificar(cliente, userRef, code, op = {}) {
  const { clientIp, ...resto } = op;
  return cliente.post('/api/v1/verify', { user_ref: userRef, code, ...(clientIp ? { client_ip: clientIp } : {}) }, resto);
}

/** Cuerpo y cabeceras relevantes de una respuesta, para comparar si dos respuestas son indistinguibles. */
export function firmaRespuesta(r) {
  const h = r.cabeceras ?? {};
  return JSON.stringify({
    status: r.status, cuerpo: r.cuerpo,
    cabeceras: { 'content-type': h['content-type'] ?? null, 'retry-after': h['retry-after'] ?? null, 'cache-control': h['cache-control'] ?? null },
  });
}

/**
 * Verifica con un usuario de prueba y, si se acepta, registra la deriva que devuelve el servidor
 * (drift_steps) para que los siguientes códigos caigan dentro de su ventana.
 */
export async function verificarUsuario(cliente, usuario, code, op = {}) {
  const r = await verificar(cliente, usuario.userRef, code, op);
  if (r.status === 200 && Number.isInteger(r.cuerpo?.drift_steps)) usuario.deriva = r.cuerpo.drift_steps;
  return r;
}

/** POST /api/v1/tokens/validate. */
export const validarToken = (cliente, token, consumirJti = true, op = {}) =>
  cliente.post('/api/v1/tokens/validate', consumirJti === undefined ? { token } : { token, consume_jti: consumirJti }, op);

/**
 * Lee /metrics (formato texto de Prometheus; el servicio solo lo expone a localhost o a la consola).
 * @returns {Promise<Map<string, number> | null>} null si no está disponible
 */
export async function leerMetricas(cliente) {
  // /metrics solo se sirve a 127.0.0.1/::1 exactos: se fuerza ese origen aunque el escenario use otro.
  const r = await cliente.peticion('GET', '/metrics', { sinCredenciales: true, timeoutMs: 3000, cabeceras: { accept: 'text/plain' }, origen: '127.0.0.1' });
  if (r.status !== 200) return null;
  return analizarMetricas(r.texto);
}

/** Analiza el formato de exposición de texto en un Map "nombre{etiquetas}" → valor. */
export function analizarMetricas(texto) {
  const m = new Map();
  for (const linea of String(texto).split('\n')) {
    if (!linea || linea.startsWith('#')) continue;
    const i = linea.lastIndexOf(' ');
    if (i <= 0) continue;
    const valor = Number(linea.slice(i + 1));
    if (Number.isFinite(valor)) m.set(linea.slice(0, i).trim(), valor);
  }
  return m;
}

/** Suma las series cuyo nombre empieza por `prefijo` y cuya clave contiene `filtro`. */
export function sumarMetrica(metricas, prefijo, filtro = '') {
  if (!metricas) return null;
  let total = 0;
  for (const [k, v] of metricas) if (k.startsWith(prefijo) && k.includes(filtro)) total += v;
  return total;
}

/** Diferencia de una serie entre dos lecturas (null si alguna falta). */
export function deltaMetrica(antes, despues, prefijo, filtro = '') {
  const a = sumarMetrica(antes, prefijo, filtro);
  const d = sumarMetrica(despues, prefijo, filtro);
  return a === null || d === null ? null : d - a;
}

/** Busca rastros de errores internos en un texto de respuesta (pilas, rutas, mensajes de Node). */
export function filtraDetallesInternos(texto) {
  return /\bat [\w.<>]+ \(|node:internal|\/src\/[\w/.-]+\.js|SQLITE_|TypeError|ReferenceError|SyntaxError: Unexpected|"stack"/.test(String(texto));
}

/**
 * Direcciones de loopback 127.0.X.Y para simular orígenes distintos sin salir de la máquina.
 * En Linux todo 127.0.0.0/8 es local, así que el servidor ve IP de origen reales y distintas.
 * @param {number} n @param {number} [bloque=10] tercer octeto (separa escenarios entre sí)
 */
export function origenesSimulados(n, bloque = 10) {
  return Array.from({ length: n }, (_, i) => `127.0.${bloque + Math.floor(i / 250)}.${(i % 250) + 2}`);
}

/** ¿Podemos salir por otra dirección de loopback? (Linux sí; macOS solo con alias configurados). */
export async function soportaOrigenes(cliente, origen = '127.0.99.2') {
  const r = await cliente.peticion('GET', '/health', { origen, sinCredenciales: true, timeoutMs: 2000 });
  return r.status > 0;
}
