#!/usr/bin/env node
// Escenario: origen compartido detrás de un portal integrador. Todos los ciudadanos de un portal
// llegan al servicio con la MISMA IP TCP (la del servidor del portal). Antes, el detector de
// anomalías y los límites puntuaban por esa IP: unos pocos fallos de ciudadanos distintos bastaban
// para bloquear a todo el portal. Ahora el portal envía `client_ip` (IP real del ciudadano) y el
// origen es HMAC(app_id:client_ip).
//
// Esperado:
//   1. Muchos ciudadanos distintos (mismo TCP, distinto client_ip) fallan alguna vez: NO bloquean a un
//      ciudadano legítimo que llega después con su propio client_ip.
//   2. Un atacante con un único client_ip recorre muchas cuentas: el detector bloquea ESE origen
//      (incluso con un código correcto de una cuenta sin bloqueo propio), y el ciudadano legítimo sigue
//      entrando.
//   3. (Informativo) Si el portal NO envía client_ip, todos sus usuarios comparten origen: el mismo
//      patrón de fallos frena también al legítimo. Por eso el contrato recomienda enviarlo.
// Las IP de ciudadanos son de los rangos de documentación (RFC 5737): nunca direcciones reales.

import { conOrigen, crearUsuarioPrueba, esPrincipal, exigirCredenciales, nuevoUserRef, principal } from '../lib/escenario.js';
import { codigoError, etiquetaEstado } from '../lib/http.js';
import { codigoIncorrecto, codigoNuevo } from '../lib/totp.js';
import { distribucionEstados } from '../lib/metricas.js';
import { opcionNumero } from '../lib/config.js';
import { deltaMetrica, leerMetricas, verificar, verificarUsuario } from '../lib/servicio.js';

export const id = 'origen-compartido';
export const nombre = 'Origen compartido: ciudadanos detrás del mismo portal';
export const demuestra = 'Fallos de muchos ciudadanos tras la misma IP del portal (distinto client_ip) no bloquean a un legítimo; un atacante con un único client_ip sí queda bloqueado.';

const ipCiudadano = (i) => `203.0.113.${10 + (i % 200)}`;
const IP_LEGITIMO = '198.51.100.5';
const IP_ATACANTE = '192.0.2.66';

export async function ejecutar(ctx, res) {
  exigirCredenciales(ctx);
  const { cliente, config } = ctx;
  const nCiudadanos = opcionNumero(config, 'ciudadanos', 24);
  const fallosPorCiudadano = opcionNumero(config, 'fallos-por-ciudadano', 2);
  const nCuentasAtacadas = opcionNumero(config, 'cuentas-atacadas', 20);
  const portal = cliente; // una sola IP TCP para todo: la del «servidor del portal»
  res.metrica('IP TCP del portal', cliente.origen ?? 'la de esta máquina');

  const legitimo = await crearUsuarioPrueba(ctx);
  const ciudadanos = [];
  for (let i = 0; i < Math.min(nCiudadanos, 8); i++) ciudadanos.push(await crearUsuarioPrueba(ctx));
  const objetivos = Array.from({ length: nCiudadanos }, (_, i) => ciudadanos[i] ?? { userRef: nuevoUserRef('ciudadano'), datos: null });
  const metricasAntes = await leerMetricas(cliente);

  // 1. Ciudadanos distintos (mismo TCP, distinto client_ip) que se equivocan de código.
  const fallos = [];
  for (let ronda = 0; ronda < fallosPorCiudadano; ronda++) {
    for (const [i, o] of objetivos.entries()) {
      fallos.push(await verificar(portal, o.userRef, codigoIncorrecto(o.datos ?? legitimo.datos), { clientIp: ipCiudadano(i) }));
    }
  }
  res.metrica('fallos de ciudadanos tras el portal', `${fallos.length} (${nCiudadanos} client_ip distintos × ${fallosPorCiudadano})`);
  res.verificar('Fallos de ciudadanos', 'todos 401 (ninguno bloqueado: cada uno es su propio origen)',
    JSON.stringify(distribucionEstados(fallos)), fallos.every((r) => r.status === 401));
  const c1 = await codigoNuevo(legitimo, { ventana: config.ventana });
  const ok1 = await verificarUsuario(portal, legitimo, c1.codigo, { clientIp: IP_LEGITIMO });
  res.verificar('Ciudadano legítimo tras los fallos de otros (mismo portal)', '200', `${etiquetaEstado(ok1)} ${codigoError(ok1) ?? ''}`.trim(), ok1.status === 200);
  if (ok1.status !== 200) res.hallazgo('Fallos de otros ciudadanos del mismo portal bloquearon a un ciudadano legítimo.');

  // 2. Atacante con un único client_ip contra muchas cuentas (una real sin fallos propios incluida).
  const victimaReal = await crearUsuarioPrueba(ctx);
  const cuentas = [victimaReal, ...Array.from({ length: nCuentasAtacadas - 1 }, () => ({ userRef: nuevoUserRef('victima'), datos: null }))];
  const ataque = [];
  for (let ronda = 0; ronda < 2; ronda++) {
    for (const o of cuentas) ataque.push(await verificar(portal, o.userRef, codigoIncorrecto(o.datos ?? legitimo.datos), { clientIp: IP_ATACANTE }));
  }
  const bloqueosAtaque = ataque.filter((r) => r.status === 429).length;
  res.metrica('respuestas al atacante', distribucionEstados(ataque));
  const cv = await codigoNuevo(victimaReal, { ventana: config.ventana });
  const conCodigo = await verificarUsuario(portal, victimaReal, cv.codigo, { clientIp: IP_ATACANTE });
  const metricasDespues = await leerMetricas(cliente);
  const anomalias = deltaMetrica(metricasAntes, metricasDespues, 'totp_verifications_total', 'anomaly');
  res.verificar('Atacante con un único client_ip', 'bloqueado por el detector (429 y Δ anomaly_blocked > 0)',
    `${bloqueosAtaque} × 429 · Δ anomaly_blocked ${anomalias ?? '—'}`, bloqueosAtaque > 0 && (anomalias ?? 0) > 0);
  res.verificar('Código correcto desde el origen del atacante', '429 (el origen está bloqueado, no la cuenta)',
    `${etiquetaEstado(conCodigo)} ${codigoError(conCodigo) ?? ''}`.trim(), conCodigo.status === 429);
  const c2 = await codigoNuevo(legitimo, { ventana: config.ventana });
  const ok2 = await verificarUsuario(portal, legitimo, c2.codigo, { clientIp: IP_LEGITIMO });
  res.verificar('Ciudadano legítimo durante el ataque (mismo portal, otro client_ip)', '200', `${etiquetaEstado(ok2)} ${codigoError(ok2) ?? ''}`.trim(), ok2.status === 200);
  if (ok2.status !== 200) res.hallazgo('El bloqueo de un atacante tras el portal alcanzó a un ciudadano legítimo del mismo portal.');
  const victimaLibre = await verificar(portal, victimaReal.userRef, (await codigoNuevo(victimaReal, { ventana: config.ventana })).codigo, { clientIp: '198.51.100.77' });
  res.verificar('La víctima, desde su propio client_ip', '200 (su cuenta no quedó bloqueada por el ataque)', etiquetaEstado(victimaLibre), victimaLibre.status === 200);

  // 3. Contraste informativo: un portal que NO envía client_ip (todos comparten la IP TCP).
  if (await ctx.puedeSimularOrigenes()) {
    const sinIp = conOrigen(ctx.cliente, ctx.ip(90));
    const otro = await crearUsuarioPrueba(ctx);
    const r = [];
    for (let ronda = 0; ronda < fallosPorCiudadano; ronda++) {
      for (const o of objetivos) r.push(await verificar(sinIp, o.userRef, codigoIncorrecto(o.datos ?? legitimo.datos)));
    }
    const c3 = await codigoNuevo(otro, { ventana: config.ventana });
    const sin = await verificarUsuario(sinIp, otro, c3.codigo);
    res.verificar('Contraste: mismo patrón SIN client_ip (portal no lo envía)', 'el legítimo comparte origen y puede quedar frenado',
      `${r.filter((x) => x.status === 429).length} × 429 en los fallos; legítimo → ${etiquetaEstado(sin)}`, null);
    res.nota('Sin client_ip todos los usuarios del integrador comparten origen (la IP de su servidor): el contrato recomienda enviarlo siempre.');
  }
}

export default { id, nombre, demuestra, ejecutar };
if (esPrincipal(import.meta.url)) await principal({ id, nombre, demuestra, ejecutar });
