// Resume un perfil de CPU de V8 (--cpu-prof): porcentaje de tiempo propio por función y por categoría.
// Uso: node perfil.js <archivo.cpuprofile> [n] [ultimos_segundos]
// ultimos_segundos: analiza solo el final del perfil (p. ej. la fase de verify, sin el enrolamiento).

import { readFileSync } from 'node:fs';

const perfil = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const n = Number(process.argv[3] ?? 20);
const nodos = new Map(perfil.nodes.map((x) => [x.id, x]));
const desde = perfil.endTime - Number(process.argv[4] ?? Infinity) * 1e6;
const tiempo = new Map();
let marca = perfil.startTime;
perfil.samples.forEach((id, i) => {
  marca += perfil.timeDeltas[i] ?? 0;
  if (marca >= desde) tiempo.set(id, (tiempo.get(id) ?? 0) + (perfil.timeDeltas[i] ?? 0));
});
const total = [...tiempo.values()].reduce((a, b) => a + b, 0);

/** Categoría legible de cada marco de pila. */
function categoria({ functionName: f, url }) {
  if (f === '(idle)') return 'Inactivo (esperando E/S o peticiones)';
  if (f === '(garbage collector)') return 'Recolector de basura';
  if (f === '(program)') return 'Motor V8 / nativo sin atribuir';
  if (/^(run|get|all|exec|prepare)$/.test(f) && !url) return 'SQLite (llamadas nativas node:sqlite)';
  if (/^(sign|verify|createHmac|digest|update|final|scrypt|createPrivateKey|createPublicKey|randomUUID|randomBytes|timingSafeEqual)$/.test(f) && !url) return 'Criptografía nativa';
  if (/node:(_tls|tls|internal\/tls|internal\/crypto)/.test(url) || f === 'writev' || f === 'writeUtf8String' || f === 'writeBuffer') return 'TLS y escritura de sockets';
  if (/node:(_http|http|internal\/http|net|internal\/stream|internal\/streams|events|internal\/event)/.test(url) || f === 'parserOnHeadersComplete' || f === 'execute') return 'HTTP y flujos de Node';
  if (/backend\/src\/heuristics\//.test(url)) return 'Detector local de anomalías';
  if (/backend\/src\/infrastructure\/persistence\//.test(url)) return 'Repositorios SQLite (JS)';
  if (/backend\/src\/audit\//.test(url)) return 'Bitácora y métricas';
  if (/backend\/src\//.test(url)) return 'Resto del código del servicio';
  if (f === 'parse' || f === 'stringify') return 'JSON';
  return 'Otros (Node)';
}

const porFuncion = new Map();
const porCategoria = new Map();
for (const [id, t] of tiempo) {
  const cf = nodos.get(id).callFrame;
  const k = `${cf.functionName || '(anónima)'} ${cf.url.replace(/^.*\/backend\//, 'backend/')}:${cf.lineNumber + 1}`;
  porFuncion.set(k, (porFuncion.get(k) ?? 0) + t);
  const c = categoria(cf);
  porCategoria.set(c, (porCategoria.get(c) ?? 0) + t);
}
const top = (m, k) => [...m].sort((a, b) => b[1] - a[1]).slice(0, k).map(([x, t]) => `${(100 * t / total).toFixed(1).padStart(5)} %  ${x}`).join('\n');
console.log(`Tiempo perfilado: ${(total / 1e6).toFixed(1)} s\n\nPor categoría:\n${top(porCategoria, 30)}\n\nFunciones con más tiempo propio:\n${top(porFuncion, n)}`);
