#!/usr/bin/env node
// Escenario: ataque de repetición (replay). Un código TOTP aceptado una vez debe rechazarse si se
// reenvía dentro de su ventana, incluso si dos peticiones idénticas llegan a la vez (carrera).

import { crearUsuarioPrueba, esPrincipal, exigirCredenciales, principal } from '../lib/escenario.js';
import { codigoError, etiquetaEstado } from '../lib/http.js';
import { codigoNuevo } from '../lib/totp.js';
import { resumenLatencias } from '../lib/metricas.js';
import { verificar, verificarUsuario } from '../lib/servicio.js';

export const id = 'replay';
export const nombre = 'Replay de código TOTP';
export const demuestra = 'Un código ya aceptado se rechaza al reenviarlo (anti-replay atómico: last_step < T), también en carrera concurrente.';

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

  // 2. Mismo código otra vez: debe rechazarse.
  const segunda = await verificar(cliente, usuario.userRef, codigo);
  latencias.push(segunda.ms);
  res.verificar('Reenvío del mismo código', '401 (REPLAY_DETECTED)', `${etiquetaEstado(segunda)} ${codigoError(segunda) ?? ''}`.trim(),
    segunda.status !== 200 && segunda.status >= 400 && segunda.status < 500);
  if (segunda.status === 200) res.hallazgo('El servicio aceptó dos veces el mismo código TOTP (replay).');

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

  res.metrica('respuesta del replay', segunda.cuerpo?.error ?? segunda.cuerpo?.errorCode ?? '—');
  res.metrica('latencia verificación', resumenLatencias(latencias));
}

export default { id, nombre, demuestra, ejecutar };
if (esPrincipal(import.meta.url)) await principal({ id, nombre, demuestra, ejecutar });
