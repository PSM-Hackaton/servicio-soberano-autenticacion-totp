#!/usr/bin/env node
// Proxy TCP de caos (node:net) entre el cliente y el servicio. Reenvía bytes sin descifrar (el TLS
// va de extremo a extremo) y puede:
//   · añadir latencia (RTT extra, repartido mitad por sentido) con variación opcional (jitter);
//   · cortar: cierra las conexiones activas y rechaza las nuevas (corte total de red);
//   · perder un % de conexiones nuevas: "reset" (se cierran al instante) o "silencio" (se aceptan
//     y nunca se reenvían: el cliente agota su tiempo de espera, como un paquete perdido).
//
// Uso como script:
//   node attack-lab/caos/proxy-caos.js --escuchar 9443 --destino localhost:8443 [--latencia 800]
//        [--jitter 100] [--perdida 30 --modo-perdida silencio] [--corte]
// Teclas: l latencia on/off · +/- latencia ±100 ms · c corte on/off · p pérdida 0→10→30→50→100 %
//         m modo de pérdida · k matar conexiones activas · r restaurar todo · s estadísticas · q salir
//
// Como módulo: crearProxyCaos({ puertoEscucha, destino: { host, port } }) → { iniciar, detener, configurar, ... }

import net from 'node:net';
import { analizarArgumentos, esHostLocal } from '../lib/config.js';
import { esPrincipal } from '../lib/escenario.js';

/**
 * @typedef {{ latenciaMs: number, jitterMs: number, corte: boolean, perdidaPct: number, modoPerdida: 'reset' | 'silencio' }} EstadoCaos
 */

/**
 * @param {{ hostEscucha?: string, puertoEscucha?: number, destino: { host: string, port: number },
 *           direccionSalida?: string, permitirHost?: boolean, azar?: () => number, alCambiar?: (e: EstadoCaos) => void }} opciones
 *   direccionSalida: dirección local con la que el proxy se conecta al destino (p. ej. 127.0.0.60).
 */
export function crearProxyCaos({ hostEscucha = '127.0.0.1', puertoEscucha = 0, destino, direccionSalida, permitirHost = false, azar = Math.random, alCambiar }) {
  if (!destino?.host || !destino?.port) throw new Error('Se requiere destino { host, port }');
  if (!esHostLocal(destino.host) && !permitirHost) {
    throw new Error(`Destino ${destino.host} rechazado: el proxy de caos solo apunta a localhost (usa --permitir-host en entornos propios).`);
  }

  /** @type {EstadoCaos} */
  const estado = { latenciaMs: 0, jitterMs: 0, corte: false, perdidaPct: 0, modoPerdida: 'reset' };
  const stats = { aceptadas: 0, reenviadas: 0, rechazadasCorte: 0, perdidas: 0, cortadas: 0, erroresDestino: 0, bytesSubida: 0, bytesBajada: 0 };
  /** @type {Set<{ cliente: net.Socket, servidor: net.Socket | null }>} */
  const activas = new Set();

  /** Retardo de un sentido para el estado actual. */
  const retardo = () => {
    if (estado.latenciaMs <= 0 && estado.jitterMs <= 0) return 0;
    const j = estado.jitterMs ? (azar() * 2 - 1) * estado.jitterMs : 0;
    return Math.max(0, (estado.latenciaMs + j) / 2);
  };

  /**
   * Bombea datos de `origen` a `destinoSock` respetando el orden aunque haya latencia y jitter:
   * cola FIFO por sentido; cada trozo sale como pronto en (llegada + retardo) y nunca antes que el anterior.
   */
  function bombear(origen, destinoSock, contador) {
    /** @type {{ cuando: number, trozo: Buffer | null }[]} */
    const cola = [];
    let temporizador = null;
    let ultimo = 0;
    const vaciar = () => {
      temporizador = null;
      const ahora = Date.now();
      while (cola.length && cola[0].cuando <= ahora) {
        const { trozo } = /** @type {{ trozo: Buffer | null }} */ (cola.shift());
        if (destinoSock.destroyed) continue;
        if (trozo === null) destinoSock.end(); else destinoSock.write(trozo);
      }
      if (cola.length) temporizador = setTimeout(vaciar, cola[0].cuando - ahora);
    };
    const encolar = (trozo) => {
      const r = retardo();
      if (r === 0 && cola.length === 0) {
        if (trozo === null) destinoSock.end(); else destinoSock.write(trozo);
        return;
      }
      ultimo = Math.max(Date.now() + r, ultimo);
      cola.push({ cuando: ultimo, trozo });
      if (!temporizador) temporizador = setTimeout(vaciar, Math.max(0, cola[0].cuando - Date.now()));
    };
    origen.on('data', (trozo) => { stats[contador] += trozo.length; encolar(trozo); });
    origen.on('end', () => encolar(null));
    origen.on('close', () => { if (temporizador) clearTimeout(temporizador); temporizador = null; cola.length = 0; });
  }

  const servidor = net.createServer((cliente) => {
    stats.aceptadas++;
    cliente.on('error', () => {});
    if (estado.corte) {
      stats.rechazadasCorte++;
      cliente.destroy();
      return;
    }
    if (estado.perdidaPct > 0 && azar() * 100 < estado.perdidaPct) {
      stats.perdidas++;
      if (estado.modoPerdida === 'reset') { cliente.resetAndDestroy?.() ?? cliente.destroy(); return; }
      // Silencio: se acepta y se ignora; se registra como activa para poder cortarla.
      const par = { cliente, servidor: null };
      activas.add(par);
      cliente.on('data', () => {});
      cliente.on('close', () => activas.delete(par));
      return;
    }
    const par = { cliente, servidor: /** @type {net.Socket | null} */ (null) };
    activas.add(par);
    cliente.on('close', () => { par.servidor?.destroy(); activas.delete(par); });
    cliente.pause();
    const conectar = () => {
      if (cliente.destroyed) return;
      const s = net.connect({ host: destino.host, port: destino.port, ...(direccionSalida ? { localAddress: direccionSalida, family: 4 } : {}) });
      par.servidor = s;
      s.on('connect', () => {
        stats.reenviadas++;
        bombear(cliente, s, 'bytesSubida');
        bombear(s, cliente, 'bytesBajada');
        cliente.resume();
      });
      s.on('error', () => { stats.erroresDestino++; cliente.destroy(); });
      s.on('close', () => cliente.destroy());
    };
    const r = retardo();
    if (r > 0) setTimeout(conectar, r); else conectar();
  });

  function cortarConexiones() {
    let n = 0;
    for (const par of activas) {
      par.cliente.destroy();
      par.servidor?.destroy();
      n++;
    }
    activas.clear();
    stats.cortadas += n;
    return n;
  }

  /** @param {Partial<EstadoCaos>} cambios */
  function configurar(cambios) {
    Object.assign(estado, cambios);
    if (cambios.corte) cortarConexiones();
    alCambiar?.({ ...estado });
    return { ...estado };
  }

  return {
    /** @returns {Promise<{ host: string, port: number }>} */
    iniciar() {
      return new Promise((resolver, rechazar) => {
        servidor.once('error', rechazar);
        servidor.listen(puertoEscucha, hostEscucha, () => {
          servidor.off('error', rechazar);
          const a = /** @type {net.AddressInfo} */ (servidor.address());
          resolver({ host: a.address, port: a.port });
        });
      });
    },
    detener() {
      cortarConexiones();
      return new Promise((r) => servidor.close(() => r(undefined)));
    },
    configurar,
    cortarConexiones,
    /** Restaura el tráfico normal (sin latencia, sin corte, sin pérdidas). */
    restaurar: () => configurar({ latenciaMs: 0, jitterMs: 0, corte: false, perdidaPct: 0 }),
    get estado() { return { ...estado }; },
    get estadisticas() { return { ...stats, activas: activas.size }; },
    get direccion() { return servidor.address(); },
  };
}

/** "localhost:8443" → { host, port } */
export function analizarDestino(texto) {
  const m = /^\[?([^\]]+?)\]?:(\d+)$/.exec(String(texto));
  if (!m) throw new Error(`Destino inválido "${texto}" (formato host:puerto)`);
  return { host: m[1], port: Number(m[2]) };
}

async function cli() {
  const { opciones: o } = analizarArgumentos(process.argv.slice(2));
  const destino = analizarDestino(o.destino ?? 'localhost:8443');
  const proxy = crearProxyCaos({
    puertoEscucha: Number(o.escuchar ?? 9443),
    destino,
    permitirHost: Boolean(o['permitir-host']),
    alCambiar: (e) => console.log(`[caos] latencia=${e.latenciaMs} ms jitter=${e.jitterMs} ms corte=${e.corte ? 'SÍ' : 'no'} pérdida=${e.perdidaPct} % (${e.modoPerdida})`),
  });
  const dir = await proxy.iniciar();
  console.log(`[caos] escuchando en ${dir.host}:${dir.port} → ${destino.host}:${destino.port}`);
  proxy.configurar({
    latenciaMs: Number(o.latencia ?? 0), jitterMs: Number(o.jitter ?? 0), corte: Boolean(o.corte),
    perdidaPct: Number(o.perdida ?? 0), modoPerdida: o['modo-perdida'] === 'silencio' ? 'silencio' : 'reset',
  });

  const salir = async () => { await proxy.detener(); process.exit(0); };
  process.on('SIGINT', salir);
  process.on('SIGTERM', salir);
  if (!process.stdin.isTTY) return;
  console.log('[caos] teclas: l latencia · +/- ±100 ms · c corte · p pérdida · m modo pérdida · k matar conexiones · r restaurar · s estadísticas · q salir');
  const pasosPerdida = [0, 10, 30, 50, 100];
  let ultimaLatencia = Number(o.latencia ?? 0) || 800;
  process.stdin.setRawMode(true);
  process.stdin.resume();
  process.stdin.on('data', (b) => {
    const t = b.toString();
    const e = proxy.estado;
    if (t === 'q' || t === '\u0003') salir();
    else if (t === 'l') {
      if (e.latenciaMs > 0) { ultimaLatencia = e.latenciaMs; proxy.configurar({ latenciaMs: 0 }); } else proxy.configurar({ latenciaMs: ultimaLatencia });
    } else if (t === '+') proxy.configurar({ latenciaMs: e.latenciaMs + 100 });
    else if (t === '-') proxy.configurar({ latenciaMs: Math.max(0, e.latenciaMs - 100) });
    else if (t === 'c') proxy.configurar({ corte: !e.corte });
    else if (t === 'p') proxy.configurar({ perdidaPct: pasosPerdida[(pasosPerdida.indexOf(e.perdidaPct) + 1) % pasosPerdida.length] });
    else if (t === 'm') proxy.configurar({ modoPerdida: e.modoPerdida === 'reset' ? 'silencio' : 'reset' });
    else if (t === 'k') console.log(`[caos] ${proxy.cortarConexiones()} conexiones cortadas`);
    else if (t === 'r') proxy.restaurar();
    else if (t === 's') console.log('[caos]', proxy.estadisticas);
  });
}

if (esPrincipal(import.meta.url)) {
  cli().catch((e) => { console.error(`Error: ${e.message}`); process.exit(2); });
}
