#!/usr/bin/env node
// Escenario: ataque de repetición (replay). Un código TOTP aceptado una vez debe rechazarse si se
// reenvía dentro de su ventana, incluso si dos peticiones idénticas llegan a la vez (carrera). Además
// el rechazo debe ser INDISTINGUIBLE de un código incorrecto (sin oráculo que confirme que el código
// robado fue válido), mientras el servicio lo registra internamente como replay (/metrics).

import { crearUsuarioPrueba, esPrincipal, exigirCredenciales, principal } from '../lib/escenario.js';
import { codigoError, etiquetaEstado } from '../lib/http.js';
import { codigoIncorrecto, codigoNuevo } from '../lib/totp.js';
import { resumenLatencias } from '../lib/metricas.js';
import { deltaMetrica, firmaRespuesta, leerMetricas, verificar, verificarUsuario } from '../lib/servicio.js';

export const id = 'replay';
export const nombre = 'Replay de código TOTP';
export const demuestra = 'Un código ya aceptado se rechaza al reenviarlo (anti-replay atómico: last_step < T), también en carrera concurrente; el rechazo es idéntico al de un código incorrecto (sin oráculo) y queda registrado internamente.';

export async function ejecutar(ctx, res) {
  exigirCredenciales(ctx);
  const { cliente } = ctx;
  const usuario = await crearUsuarioPrueba(ctx);
  const latencias = [];

  // 1. Código legítimo: debe aceptarse.
  const { codigo } = await codigoNuevo(usuario, { ventana: ctx.config.ventana });
  const primera = await verificarUsuario(cliente, usuario, codigo);
  latencias.push(primera.ms);
  res.verificar('Primer uso del código', '200 + JWT', `${etiquetaEstado(primera)}${primera.cuerpo?.token ? ' + JWT' : ''}`,
    primera.status === 200 && typeof primera.cuerpo?.token === 'string');

  // 2. Mismo código otra vez: debe rechazarse… exactamente igual que un código incorrecto.
  const metricasAntes = await leerMetricas(cliente);
  const segunda = await verificar(cliente, usuario.userRef, codigo);
  latencias.push(segunda.ms);
  res.verificar('Reenvío del mismo código', '401 VERIFICATION_FAILED', `${etiquetaEstado(segunda)} ${codigoError(segunda) ?? ''}`.trim(),
    segunda.status === 401 && codigoError(segunda) === 'VERIFICATION_FAILED');
  if (segunda.status === 200) res.hallazgo('El servicio aceptó dos veces el mismo código TOTP (replay).');
  const incorrecto = await verificar(cliente, usuario.userRef, codigoIncorrecto(usuario.datos));
  const iguales = firmaRespuesta(segunda) === firmaRespuesta(incorrecto);
  res.verificar('Replay indistinguible de un código incorrecto', 'mismo status, cuerpo y cabeceras (sin Retry-After)',
    iguales ? `idénticos: ${segunda.status} ${JSON.stringify(segunda.cuerpo)}` : `distintos: ${firmaRespuesta(segunda)} ≠ ${firmaRespuesta(incorrecto)}`,
    iguales && segunda.cabeceras['retry-after'] === undefined);
  if (!iguales) res.hallazgo('El rechazo de un replay difiere del de un código incorrecto: oráculo de códigos válidos.');
  const metricasDespues = await leerMetricas(cliente);
  const deltaReplay = deltaMetrica(metricasAntes, metricasDespues, 'totp_verifications_total', 'replay');
  res.verificar('El replay queda registrado internamente', 'Δ totp_verifications_total{resultado="replay"} = 1',
    deltaReplay ?? 'métricas no disponibles', deltaReplay === 1);

  // 3. Carrera: el mismo código nuevo enviado 10 veces en paralelo → como mucho 1 aceptado.
  const { codigo: codigoCarrera } = await codigoNuevo(usuario, { ventana: ctx.config.ventana });
  const paralelas = await Promise.all(Array.from({ length: 10 }, () => verificarUsuario(cliente, usuario, codigoCarrera)));
  latencias.push(...paralelas.map((r) => r.ms));
  const aceptadas = paralelas.filter((r) => r.status === 200).length;
  const internos = paralelas.filter((r) => r.status >= 500).length;
  res.verificar('Carrera: 10 envíos simultáneos del mismo código', 'exactamente 1 aceptado, 0 errores 5xx',
    `${aceptadas} aceptado(s), ${internos} 5xx`, aceptadas === 1 && internos === 0);
  if (aceptadas > 1) res.hallazgo(`Condición de carrera: ${aceptadas} verificaciones aceptadas con el mismo código.`);

  // 4. Un código ANTERIOR (ya superado por uno más nuevo) tampoco vale.
  const viejo = await verificar(cliente, usuario.userRef, codigo);
  res.verificar('Código anterior tras aceptar uno más nuevo', 'rechazado', etiquetaEstado(viejo), viejo.status !== 200);

  res.metrica('respuesta del replay', JSON.stringify(segunda.cuerpo));
  res.metrica('latencia verificación', resumenLatencias(latencias));
}

export default { id, nombre, demuestra, ejecutar };
if (esPrincipal(import.meta.url)) await principal({ id, nombre, demuestra, ejecutar });
