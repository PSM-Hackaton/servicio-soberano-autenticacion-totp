#!/usr/bin/env node
// Escenario de caos: durante una ráfaga continua de verificaciones a través del proxy de caos:
//   fase 1 «base» (normal) → fase 2 latencia 800 ms → fase 3 corte total 10 s → fase 4 restauración.
// Mide errores, tiempos de espera y latencias por fase, y el tiempo de recuperación tras el corte.
// CONFIRMA que ninguna verificación con código incorrecto fue aprobada (falla cerrado) y que el
// titular legítimo no obtiene acceso durante el corte pero sí al volver la red.
// El cliente se comporta como el SDK: tiempo de espera de 3 s y un reintento con la misma
// Idempotency-Key.
// Opciones: --latencia 800 --duracion-corte 10 --duracion-base 5 --duracion-latencia 8
//           --trabajadores 2 --pausa-ms 400 --puerto-proxy 0 (aleatorio)

import { randomUUID } from 'node:crypto';
import { crearUsuarioPrueba, esPrincipal, exigirCredenciales, nuevoUserRef, principal } from '../lib/escenario.js';
import { etiquetaEstado } from '../lib/http.js';
import { codigoIncorrecto, codigoNuevo } from '../lib/totp.js';
import { cronometro, distribucionEstados, dormir, redondear, resumenLatencias } from '../lib/metricas.js';
import { opcionNumero } from '../lib/config.js';
import { verificar } from '../lib/servicio.js';
import { crearProxyCaos } from './proxy-caos.js';

export const id = 'caos';
export const nombre = 'Caos de red: latencia, corte y restauración';
export const demuestra = 'Con latencia y cortes de red el servicio falla cerrado: ningún código incorrecto se aprueba, nadie entra durante el corte y se recupera solo en segundos.';

const TIMEOUT_SDK_MS = 3000;

/** Verificación al estilo SDK: 3 s de espera y un reintento con la misma clave de idempotencia. */
async function verificarComoSdk(cliente, userRef, code) {
  const cabeceras = { 'idempotency-key': `lab-${randomUUID()}` };
  const r1 = await verificar(cliente, userRef, code, { cabeceras, timeoutMs: TIMEOUT_SDK_MS });
  if (r1.status !== 0) return { ...r1, intentos: 1 };
  const r2 = await verificar(cliente, userRef, code, { cabeceras, timeoutMs: TIMEOUT_SDK_MS });
  return { ...r2, ms: r1.ms + r2.ms, intentos: 2 };
}

export async function ejecutar(ctx, res) {
  exigirCredenciales(ctx);
  const { config } = ctx;
  const latencia = opcionNumero(config, 'latencia', 800);
  const msCorte = opcionNumero(config, 'duracion-corte', 10) * 1000;
  const msBase = opcionNumero(config, 'duracion-base', 5) * 1000;
  const msLatencia = opcionNumero(config, 'duracion-latencia', 8) * 1000;
  const trabajadores = opcionNumero(config, 'trabajadores', 2);
  const pausa = opcionNumero(config, 'pausa-ms', 400);

  // Dos proxies de caos con la MISMA configuración en cada fase (la «red» entre el sistema
  // institucional y el servicio): uno para la ráfaga de ataque y otro para el titular legítimo.
  // Cada uno sale por su propia IP de loopback: sin client_ip, el detector local de anomalías y el
  // límite por origen puntúan por (app, IP de conexión) y, si compartieran IP, frenarían al titular
  // por culpa de la ráfaga (429), ocultando lo que aquí se mide (el comportamiento ante fallos de red).
  const multiorigen = await ctx.puedeSimularOrigenes();
  if (!multiorigen) res.nota('Sin orígenes simulados: ráfaga y titular comparten IP y el detector puede bloquear al titular (429).');
  const destino = { host: config.destino.hostname, port: Number(config.destino.port || 443) };
  const crear = (n, puerto = 0) => crearProxyCaos({
    puertoEscucha: puerto, destino, direccionSalida: multiorigen ? ctx.ip(n) : undefined, permitirHost: config.permitirHost,
  });
  const proxyRafaga = crear(60, opcionNumero(config, 'puerto-proxy', 0));
  const proxyTitular = crear(61);
  const proxies = [proxyRafaga, proxyTitular];
  const proxy = { configurar: (c) => proxies.forEach((p) => p.configurar(c)) };
  const [dirR, dirT] = [await proxyRafaga.iniciar(), await proxyTitular.iniciar()];
  const viaProxy = ctx.clienteHacia(`${config.destino.protocol}//localhost:${dirR.port}`, { timeoutMs: TIMEOUT_SDK_MS, keepAlive: true });
  const titularViaProxy = ctx.clienteHacia(`${config.destino.protocol}//localhost:${dirT.port}`, { timeoutMs: TIMEOUT_SDK_MS, keepAlive: true });
  res.metrica('proxies de caos', `ráfaga 127.0.0.1:${dirR.port} · titular 127.0.0.1:${dirT.port} → ${config.destino.host}`);

  try {
    // Preparación (directa, sin caos): objetivos de códigos incorrectos y un titular legítimo por fase.
    const objetivos = [await crearUsuarioPrueba(ctx), await crearUsuarioPrueba(ctx)];
    const fases = [
      { nombre: 'base', ms: msBase, conf: { latenciaMs: 0, corte: false } },
      { nombre: `latencia ${latencia} ms`, ms: msLatencia, conf: { latenciaMs: latencia, corte: false } },
      { nombre: `corte total ${msCorte / 1000} s`, ms: msCorte, conf: { latenciaMs: 0, corte: true } },
      { nombre: 'restauración', ms: 0, conf: { latenciaMs: 0, corte: false } },
    ];
    for (const f of fases) f.titular = await crearUsuarioPrueba(ctx);

    /** @type {{ fase: string, status: number, error: string | null, ms: number }[]} */
    const incorrectas = [];
    let faseActual = fases[0].nombre;
    let corriendo = true;

    // Ráfaga continua de códigos incorrectos (cuentas reales bloqueables + inexistentes).
    const rafaga = Array.from({ length: trabajadores }, async (_, w) => {
      let i = 0;
      while (corriendo) {
        const real = (i++ + w) % 2 === 0;
        const obj = objetivos[i % objetivos.length];
        const userRef = real ? obj.userRef : nuevoUserRef('caos');
        const fase = faseActual;
        const r = await verificar(viaProxy, userRef, codigoIncorrecto(obj.datos), { timeoutMs: TIMEOUT_SDK_MS });
        incorrectas.push({ fase, status: r.status, error: r.error, ms: r.ms, aprobada: r.status === 200 });
        await dormir(pausa);
      }
    });

    const legitimas = [];
    let tiempoRecuperacionMs = null;
    let primeraRespuestaMs = null;
    const reloj = cronometro();

    for (const f of fases) {
      faseActual = f.nombre;
      proxy.configurar(f.conf);
      const inicioFase = reloj.ms();
      ctx.log(`fase: ${f.nombre}`);

      if (f.nombre === 'restauración') {
        // Tiempo de recuperación: desde que vuelve la red hasta el primer /health 200 vía proxy.
        const t0 = performance.now();
        while (performance.now() - t0 < 60000) {
          const h = await viaProxy.get('/health', { sinCredenciales: true, timeoutMs: 1000 });
          if (h.status > 0 && primeraRespuestaMs === null) primeraRespuestaMs = performance.now() - t0;
          if (h.status === 200) { tiempoRecuperacionMs = performance.now() - t0; break; }
          await dormir(100);
        }
        await dormir(3000); // dejar que la ráfaga vuelva a fluir antes de medir al titular
      } else {
        await dormir(Math.min(1000, f.ms / 4));
      }

      // Titular legítimo con su código correcto en esta fase.
      const c = await codigoNuevo(f.titular, { ventana: config.ventana });
      const r = await verificarComoSdk(titularViaProxy, f.titular.userRef, c.codigo);
      legitimas.push({ fase: f.nombre, status: r.status, error: r.error, ms: r.ms, intentos: r.intentos });
      ctx.log(`  titular: ${etiquetaEstado(r)} en ${Math.round(r.ms)} ms (${r.intentos} intento/s)`);

      const restante = f.ms - (reloj.ms() - inicioFase);
      if (restante > 0) await dormir(restante);
      if (f.nombre === 'restauración') await dormir(2000);
    }
    corriendo = false;
    await Promise.all(rafaga);

    // ---------------- verificaciones
    const aprobadas = incorrectas.filter((r) => r.aprobada).length;
    res.verificar('Códigos INCORRECTOS aprobados durante todo el caos', '0 (falla cerrado)', `${aprobadas} de ${incorrectas.length}`, aprobadas === 0);
    if (aprobadas > 0) res.hallazgo(`${aprobadas} verificaciones con código incorrecto aprobadas durante el caos de red.`);
    const n5xx = incorrectas.filter((r) => r.status >= 500).length + legitimas.filter((r) => r.status >= 500).length;
    res.verificar('Errores internos (5xx)', '0', n5xx, n5xx === 0);

    const [lBase, lLat, lCorte, lRest] = legitimas;
    res.verificar('Titular en fase base', '200', etiquetaEstado(lBase), lBase.status === 200);
    res.verificar(`Titular con latencia ${latencia} ms`, '200 (más lento)', `${etiquetaEstado(lLat)} en ${Math.round(lLat.ms)} ms`, lLat.status === 200);
    res.verificar('Titular durante el corte', 'sin acceso (error de red, nunca 200)', `${etiquetaEstado(lCorte)} tras ${lCorte.intentos} intento/s`, lCorte.status !== 200);
    res.verificar('Titular tras restaurar', '200', etiquetaEstado(lRest), lRest.status === 200);

    const enCorte = incorrectas.filter((r) => r.fase === fases[2].nombre);
    res.verificar('Corte total efectivo', '0 respuestas HTTP durante el corte', `${enCorte.filter((r) => r.status > 0).length} de ${enCorte.length}`,
      enCorte.every((r) => r.status === 0));
    res.verificar('Tiempo de recuperación tras el corte', '< 30 s', tiempoRecuperacionMs === null ? 'no se recuperó' : `${redondear(tiempoRecuperacionMs / 1000, 2)} s`,
      tiempoRecuperacionMs !== null && tiempoRecuperacionMs < 30000);

    // ---------------- métricas por fase
    for (const f of fases) {
      const rs = incorrectas.filter((r) => r.fase === f.nombre);
      const http = rs.filter((r) => r.status > 0);
      const timeouts = rs.filter((r) => r.error === 'TIEMPO_AGOTADO').length;
      const red = rs.filter((r) => r.status === 0 && r.error !== 'TIEMPO_AGOTADO').length;
      const lat = resumenLatencias(http.map((r) => r.ms));
      res.metrica(`fase «${f.nombre}»`, `${rs.length} pet · ${http.length} con respuesta · ${timeouts} timeouts · ${red} errores de red · p50 ${lat.p50 ?? '—'} ms · p95 ${lat.p95 ?? '—'} ms`);
    }
    res.metrica('estados (ráfaga completa)', distribucionEstados(incorrectas));
    res.metrica('primera respuesta tras restaurar', primeraRespuestaMs === null ? '—' : `${Math.round(primeraRespuestaMs)} ms`);
    res.metrica('tiempo de recuperación (/health 200)', tiempoRecuperacionMs === null ? '—' : `${Math.round(tiempoRecuperacionMs)} ms`);
    res.metrica('estadísticas del proxy (ráfaga)', proxyRafaga.estadisticas);
  } finally {
    viaProxy.cerrar();
    titularViaProxy.cerrar();
    await Promise.all(proxies.map((p) => p.detener()));
  }
}

export default { id, nombre, demuestra, ejecutar };
if (esPrincipal(import.meta.url)) await principal({ id, nombre, demuestra, ejecutar });
