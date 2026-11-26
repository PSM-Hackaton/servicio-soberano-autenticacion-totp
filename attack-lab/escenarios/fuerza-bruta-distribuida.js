#!/usr/bin/env node
// Escenario: fuerza bruta DISTRIBUIDA. Muchos orígenes distintos atacan la misma cuenta, uno o dos
// intentos cada uno, para esquivar los límites por IP.
//
// Cómo se simulan las IP: el servicio NO confía en X-Forwarded-For (correcto: cualquiera podría
// falsificarla). En su lugar, cada petición sale desde una dirección de loopback distinta
// (127.0.20.2, 127.0.20.3, …), que en Linux son direcciones locales reales: el servidor ve IP de
// origen distintas sin que salga un paquete de la máquina. Si la plataforma no lo permite
// (macOS sin alias), se envía igualmente X-Forwarded-For y se documenta la limitación.
//
// Esperado: el bloqueo es POR CUENTA, así que salta igual aunque cada IP intente una sola vez, y el
// detector local de anomalías registra el patrón (verificaciones anómalas / riesgo elevado).
// Nota: aquí las IP son de CONEXIÓN distintas y sin client_ip (como varios clientes directos);
// el origen es HMAC(app_id:IP de conexión).

import { crearUsuarioPrueba, esPrincipal, exigirCredenciales, principal } from '../lib/escenario.js';
import { codigoError, etiquetaEstado } from '../lib/http.js';
import { codigoIncorrecto, codigoNuevo } from '../lib/totp.js';
import { distribucionEstados, resumenLatencias } from '../lib/metricas.js';
import { opcionNumero } from '../lib/config.js';
import { deltaMetrica, leerMetricas, verificar } from '../lib/servicio.js';

export const id = 'fuerza-bruta-distribuida';
export const nombre = 'Fuerza bruta distribuida (rotación de IP)';
export const demuestra = 'Rotar de IP no evita el bloqueo progresivo por cuenta; el detector local de anomalías registra el patrón.';

export async function ejecutar(ctx, res) {
  exigirCredenciales(ctx);
  const { cliente, config } = ctx;
  const nIps = opcionNumero(config, 'ips', 40);
  const multiorigen = await ctx.puedeSimularOrigenes();
  const ips = ctx.ips(nIps, 10);
  if (!multiorigen) {
    res.nota('La plataforma no permite salir por otras direcciones 127.x: se usa solo X-Forwarded-For, que el servicio ignora a propósito. Todas las peticiones llegan con la misma IP real.');
  }
  res.metrica('orígenes simulados', multiorigen ? `${nIps} IP de loopback reales (${ips[0]} … ${ips.at(-1)})` : 'X-Forwarded-For (ignorada por el servidor)');

  const victima = await crearUsuarioPrueba(ctx);
  const metricasAntes = await leerMetricas(cliente);
  const respuestas = [];
  let primer429 = null;

  for (let i = 0; i < ips.length; i++) {
    const op = { cabeceras: { 'x-forwarded-for': ips[i] }, ...(multiorigen ? { origen: ips[i] } : {}) };
    const r = await verificar(cliente, victima.userRef, codigoIncorrecto(victima.datos), op);
    respuestas.push(r);
    if (r.status === 429 && primer429 === null) primer429 = { intento: i + 1, codigo: codigoError(r) };
    ctx.log(`${ips[i]} → ${etiquetaEstado(r)} ${codigoError(r) ?? ''}`);
  }

  res.verificar('Bloqueo de la cuenta pese a rotar IP', `429 a partir del intento ${config.maxIntentos + 1}`,
    primer429 ? `429 en el intento ${primer429.intento} (${primer429.codigo ?? '—'})` : 'sin 429',
    primer429 !== null && primer429.intento <= config.maxIntentos + 1);
  if (!primer429) res.hallazgo(`La cuenta no se bloqueó tras ${ips.length} fallos desde ${ips.length} orígenes distintos.`);
  const aceptadas = respuestas.filter((r) => r.status === 200).length;
  res.verificar('Códigos incorrectos aceptados', '0', aceptadas, aceptadas === 0);
  res.verificar('Errores internos (5xx)', '0', respuestas.filter((r) => r.status >= 500).length, respuestas.every((r) => r.status < 500));

  // Ni el dueño legítimo con su código correcto entra mientras dura el bloqueo (falla cerrado).
  const legit = await codigoNuevo(victima, { ventana: config.ventana, esperar: false });
  if (legit) {
    const r = await verificar(cliente, victima.userRef, legit.codigo);
    res.verificar('Código correcto del titular durante el ataque', '429 (cuenta protegida)', etiquetaEstado(r), r.status === 429);
  }

  // Señal del detector local de anomalías: /metrics (solo localhost). Hacia fuera su bloqueo es el
  // mismo 429 TOO_MANY_REQUESTS genérico que el bloqueo por cuenta (no revela qué defensa actuó).
  const metricasDespues = await leerMetricas(cliente);
  const deltaAnom = deltaMetrica(metricasAntes, metricasDespues, 'totp_verifications_total', 'anomaly');
  const deltaLocked = deltaMetrica(metricasAntes, metricasDespues, 'totp_verifications_total', 'locked');
  res.metrica('Δ verificaciones bloqueadas (métrica locked)', deltaLocked ?? 'métricas no disponibles');
  res.metrica('Δ bloqueos del detector (métrica anomaly_blocked)', deltaAnom ?? 'métricas no disponibles');
  const genericos = respuestas.filter((r) => r.status === 429).every((r) => codigoError(r) === 'TOO_MANY_REQUESTS');
  res.verificar('Los 429 son genéricos', 'TOO_MANY_REQUESTS (sin detalles del detector)', genericos ? 'sí' : 'no', genericos);
  res.verificar('Detector local de anomalías', 'bloqueo adaptativo o registro del patrón',
    (deltaAnom ?? 0) > 0 ? `${deltaAnom} bloqueos del detector` : 'sin bloqueos del detector (actuó antes el bloqueo por cuenta)',
    null);
  if (!((deltaAnom ?? 0) > 0)) {
    res.nota('El bloqueo vigente de la cuenta se comprueba antes que el detector, así que con 1 intento por IP la defensa que actúa es el bloqueo por cuenta; el detector registra cada intento (bitácora y /admin/api/anomalies).');
  }
  res.metrica('estados', distribucionEstados(respuestas));
  res.metrica('latencia', resumenLatencias(respuestas.map((r) => r.ms)));
}

export default { id, nombre, demuestra, ejecutar };
if (esPrincipal(import.meta.url)) await principal({ id, nombre, demuestra, ejecutar });
