#!/usr/bin/env node
// Escenario: fuerza bruta secuencial contra UNA cuenta desde un origen.
// Esperado: tras max_intentos fallos (5) → 429 con bloqueo de 30 s; durante el bloqueo ni siquiera
// el código correcto pasa; al vencer, otros 5 fallos escalan el bloqueo a 2 min (30 s → 2 min → 10 min → 1 h).
// Opciones: --rapido (no espera los 30 s del primer escalón), --intentos-bloqueados N.

import { crearUsuarioPrueba, esPrincipal, exigirCredenciales, principal } from '../lib/escenario.js';
import { codigoError, etiquetaEstado, reintentarEn } from '../lib/http.js';
import { codigoIncorrecto, codigoNuevo } from '../lib/totp.js';
import { dormir, distribucionEstados, resumenLatencias } from '../lib/metricas.js';
import { opcionNumero } from '../lib/config.js';
import { verificar } from '../lib/servicio.js';

export const id = 'fuerza-bruta';
export const nombre = 'Fuerza bruta secuencial';
export const demuestra = 'Tras 5 fallos la cuenta se bloquea (429, 30 s) y el bloqueo escala (2 min…); un código correcto tampoco pasa durante el bloqueo.';

export async function ejecutar(ctx, res) {
  exigirCredenciales(ctx);
  const { cliente, config } = ctx;
  const maxIntentos = config.maxIntentos;
  const rapido = Boolean(config.opciones.rapido);
  const extra = opcionNumero(config, 'intentos-bloqueados', 15);
  const usuario = await crearUsuarioPrueba(ctx);
  const todas = [];
  const op = {}; // el contexto del escenario ya sale por su propia IP de loopback

  // 1. Ráfaga de códigos incorrectos hasta el primer 429.
  let primer429 = null;
  const traza = [];
  for (let i = 1; i <= maxIntentos + 3; i++) {
    const r = await verificar(cliente, usuario.userRef, codigoIncorrecto(usuario.datos), op);
    todas.push(r);
    traza.push(etiquetaEstado(r));
    ctx.log(`intento ${i}: ${etiquetaEstado(r)} ${codigoError(r) ?? ''}`);
    if (r.status === 429) { primer429 = { intento: i, segundos: reintentarEn(r), r }; break; }
  }
  res.metrica('secuencia de respuestas', traza.join(' → '));
  res.verificar(`Bloqueo tras ${maxIntentos} fallos`, `429 en el intento ${maxIntentos + 1}`,
    primer429 ? `429 en el intento ${primer429.intento}` : 'sin 429', primer429 !== null && primer429.intento <= maxIntentos + 1);
  res.verificar('Primer escalón de bloqueo', '≈30 s (Retry-After)', primer429?.segundos ?? '—',
    primer429?.segundos !== null && primer429?.segundos !== undefined && primer429.segundos >= 20 && primer429.segundos <= 31);
  if (!primer429) res.hallazgo(`Sin bloqueo tras ${maxIntentos + 3} códigos incorrectos consecutivos contra una cuenta.`);

  // 2. Durante el bloqueo: el atacante insiste y además prueba el código CORRECTO.
  const bloqueadas = [];
  for (let i = 0; i < extra; i++) bloqueadas.push(await verificar(cliente, usuario.userRef, codigoIncorrecto(usuario.datos), op));
  todas.push(...bloqueadas);
  res.verificar(`${extra} intentos más durante el bloqueo`, 'todos 429', JSON.stringify(distribucionEstados(bloqueadas)),
    bloqueadas.every((r) => r.status === 429));
  const correcto = await codigoNuevo(usuario, { ventana: config.ventana, esperar: false });
  if (correcto) {
    const r = await verificar(cliente, usuario.userRef, correcto.codigo, op);
    todas.push(r);
    res.verificar('Código CORRECTO durante el bloqueo', '429 (no se concede)', etiquetaEstado(r), r.status === 429);
    if (r.status === 200) res.hallazgo('Un código correcto fue aceptado mientras la cuenta estaba bloqueada.');
  }

  // 3. Escalada: esperar a que venza el primer escalón y fallar otras 5 veces.
  if (rapido || !primer429?.segundos) {
    res.nota('Escalada no medida (--rapido o sin bloqueo inicial). Sin --rapido se espera el primer escalón y se comprueba 30 s → 2 min.');
  } else {
    const espera = Math.min(primer429.segundos, 35) * 1000 + 1500;
    ctx.log(`esperando ${(espera / 1000).toFixed(0)} s a que venza el primer escalón…`);
    await dormir(espera);
    let segundo = null;
    for (let i = 1; i <= maxIntentos + 2; i++) {
      const r = await verificar(cliente, usuario.userRef, codigoIncorrecto(usuario.datos), op);
      todas.push(r);
      if (r.status === 429) { segundo = { intento: i, segundos: reintentarEn(r), codigo: codigoError(r) }; break; }
    }
    // Lo esperado es el escalón de 2 min; si el detector local de anomalías se adelanta (el atacante
    // siguió insistiendo durante el bloqueo) responde ANOMALY_BLOCKED con un bloqueo aún mayor.
    const porDetector = segundo?.codigo === 'ANOMALY_BLOCKED';
    res.verificar('Segundo escalón (tras vencer el primero)', '≈120 s o bloqueo del detector (más largo)',
      segundo ? `${segundo.segundos} s en el intento ${segundo.intento} (${segundo.codigo})` : 'sin 429',
      segundo !== null && ((segundo.segundos >= 90 && segundo.segundos <= 121) || (porDetector && segundo.segundos >= 120)));
    res.metrica('escalones observados', `${primer429.segundos} s → ${segundo?.segundos ?? '—'} s${porDetector ? ' (detector de anomalías)' : ''}`);
  }

  const aceptadas = todas.filter((r) => r.status === 200).length;
  res.verificar('Códigos incorrectos aceptados', '0', aceptadas, aceptadas === 0);
  res.verificar('Errores internos (5xx)', '0', todas.filter((r) => r.status >= 500).length, todas.every((r) => r.status < 500));
  res.metrica('peticiones', todas.length);
  res.metrica('estados', distribucionEstados(todas));
  res.metrica('latencia', resumenLatencias(todas.map((r) => r.ms)));
}

export default { id, nombre, demuestra, ejecutar };
if (esPrincipal(import.meta.url)) await principal({ id, nombre, demuestra, ejecutar });
