#!/usr/bin/env node
// Ejecuta todos los escenarios en orden, imprime un resumen y escribe
// attack-lab/resultados/informe-<fecha>.json y .html (autocontenido).
//
// Uso:
//   node attack-lab/ejecutar-todo.js --client-id <id> --client-secret <secreto> [--client-id-2 … --client-secret-2 …]
//        [--url https://localhost:8443] [--ca backend/certs/localhost.crt | --inseguro]
//        [--solo replay,jwt] [--omitir caos] [--rapido] [--pausa 3]
//        [--comando-arranque "node src/main.js" --pid-backend <pid>]   (activa el escenario de reinicio)

import { join } from 'node:path';
import { RAIZ_LAB, cargarConfig, opcionNumero } from './lib/config.js';
import { color, marca, tabla, titulo } from './lib/consola.js';
import { correrEscenario, crearContexto, crearResultado, imprimirResultado, sondearSalud } from './lib/escenario.js';
import { etiquetaEstado } from './lib/http.js';
import { dormir } from './lib/metricas.js';
import { escribirInforme, resumir } from './lib/informe.js';

import replay from './escenarios/replay.js';
import jwt from './escenarios/jwt.js';
import entradas from './escenarios/entradas.js';
import deriva from './escenarios/deriva.js';
import fuerzaBruta from './escenarios/fuerza-bruta.js';
import distribuida from './escenarios/fuerza-bruta-distribuida.js';
import spraying from './escenarios/spraying.js';
import origenCompartido from './escenarios/origen-compartido.js';
import inundacion from './escenarios/inundacion.js';
import caos from './caos/escenario-caos.js';
import reinicio from './caos/reinicio.js';

/** Orden pensado para que los límites que activa un escenario no estropeen los siguientes. */
export const ESCENARIOS = [replay, jwt, entradas, deriva, fuerzaBruta, distribuida, spraying, origenCompartido, inundacion, caos, reinicio];

async function main() {
  const config = cargarConfig();
  const ctx = crearContexto(config);
  const lista = (v) => (typeof v === 'string' ? v.split(',').map((s) => s.trim()).filter(Boolean) : []);
  const solo = lista(config.opciones.solo);
  const omitir = lista(config.opciones.omitir);
  const pausa = opcionNumero(config, 'pausa', 3) * 1000;
  const conReinicio = Boolean(config.opciones['comando-arranque'] || config.opciones.comando);

  console.log(titulo('Laboratorio de ataques simulados · servicio soberano TOTP'));
  console.log(`destino ${color('negrita', config.url)} · TLS ${config.inseguro ? color('amarillo', 'sin verificar (--inseguro, solo localhost)') : config.ca ? `CA ${config.ca}` : 'CA del sistema'} · apps de prueba: ${config.apps.length}`);

  const salud = await sondearSalud(ctx.cliente);
  if (salud.status !== 200) {
    console.error(color('rojo', `El servicio no responde en ${config.url}/health (${etiquetaEstado(salud)}). ¿Está arrancado? ¿CA correcta (--ca) o --inseguro?`));
    process.exitCode = 2;
    ctx.cerrar();
    return;
  }
  console.log(color('gris', `health: ${JSON.stringify(salud.cuerpo)}`));

  const inicio = Date.now();
  const resultados = [];
  for (const [indice, esc] of ESCENARIOS.entries()) {
    const omitido = (solo.length && !solo.includes(esc.id)) || omitir.includes(esc.id) || (esc.id === 'reinicio' && !conReinicio);
    if (omitido) {
      const r = crearResultado(esc.id, esc.nombre, esc.demuestra);
      r.nota(esc.id === 'reinicio' && !conReinicio ? 'Omitido: pasa --comando-arranque y --pid-backend para ejecutarlo.' : 'Omitido por --solo/--omitir.');
      resultados.push({ ...r.cerrar(), omitido: true });
      continue;
    }
    console.log(color('gris', `\n▶ ${esc.nombre}…`));
    const res = await correrEscenario(esc, ctx, indice + 1);
    resultados.push(res);
    imprimirResultado(res);
    if (pausa > 0) await dormir(pausa);
  }
  const duracionMs = Date.now() - inicio;
  const resumen = resumir(resultados, duracionMs);

  console.log(titulo('Resumen'));
  console.log(tabla(['Escenario', 'Verificaciones', 'Duración', 'Resultado'], resultados.map((r) => [
    r.nombre,
    `${r.verificaciones.filter((v) => v.ok === true).length}/${r.verificaciones.filter((v) => v.ok !== null).length}`,
    `${(r.duracionMs / 1000).toFixed(1)} s`,
    r.omitido ? color('gris', 'omitido') : marca(r.ok),
  ])));
  const hallazgos = resultados.flatMap((r) => r.hallazgos.map((h) => `[${r.id}] ${h}`));
  if (hallazgos.length) {
    console.log(color('rojo', '\nHallazgos de seguridad:'));
    for (const h of hallazgos) console.log(color('rojo', `  · ${h}`));
  }

  const informe = {
    generado: new Date().toISOString(),
    destino: config.url,
    entorno: { node: process.version, plataforma: process.platform, salud: salud.cuerpo },
    resumen,
    resultados,
  };
  const rutas = escribirInforme(informe, config.opciones.salida ? String(config.opciones.salida) : join(RAIZ_LAB, 'resultados'));
  console.log(`\n${color('negrita', `${resumen.correctos}/${resumen.evaluados} escenarios OK`)} · ${resumen.verificacionesOk}/${resumen.verificaciones} verificaciones · ${resumen.hallazgos} hallazgos · ${(duracionMs / 1000).toFixed(0)} s`);
  console.log(`informe: ${rutas.json}\n         ${rutas.html}`);
  ctx.cerrar();
  process.exitCode = resumen.fallidos.length ? 1 : 0;
}

main().catch((e) => {
  console.error(color('rojo', `Error: ${e.message}`));
  process.exitCode = 2;
});
