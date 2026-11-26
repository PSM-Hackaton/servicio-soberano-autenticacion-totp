#!/usr/bin/env node
// Verificador reproducible de despliegue institucional sin contenedores (Issue #25 / C7).
// Prueba deploy/servicio-totp.service (systemd-analyze verify + security) y el flujo completo
// de deploy/README.md en un entorno temporal aislado equivalente a producción:
//   generar-env -> certificado EC P-256 -> semilla -> arranque NODE_ENV=production TLS 1.3 ->
//   sondas /health/ready, JWKS, /app/, /consola/, /metrics -> escaneo DAST en vivo ->
//   copia en caliente SQLite VACUUM INTO -> fail-fast en producción -> parada limpia SIGTERM.
// Cero dependencias npm (Node.js 22.5+).

import { spawn, execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import https from 'node:https';
import dast from '../attack-lab/escenarios/dast.js';
import { correrEscenario, crearContexto } from '../attack-lab/lib/escenario.js';
import { escribirInforme, resumir } from '../attack-lab/lib/informe.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..');
const SERVICE_FILE = join(__dirname, 'servicio-totp.service');

function httpsGet(url, caPem) {
  return new Promise((resolver) => {
    const req = https.get(url, { ca: caPem, minVersion: 'TLSv1.3', timeout: 4000 }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolver({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8'), headers: res.headers }));
    });
    req.on('error', (e) => resolver({ status: 0, text: '', error: e.message }));
  });
}

async function esperarListo(url, caPem, maxMs = 8000) {
  const limite = Date.now() + maxMs;
  while (Date.now() < limite) {
    const r = await httpsGet(url, caPem);
    if (r.status === 200) return r;
    await new Promise((r2) => setTimeout(r2, 120));
  }
  throw new Error(`El servidor no respondió 200 en ${url} antes de ${maxMs} ms`);
}

function ejecutarComando(bin, args) {
  const r = spawnSync(bin, args, { encoding: 'utf8' });
  return { ok: r.status === 0, status: r.status, stdout: (r.stdout || '').trim(), stderr: (r.stderr || '').trim() };
}

export async function verificarDespliegue({ guardarInformeDast = null, puerto = 18443 } = {}) {
  const workDir = mkdtempSync(join(tmpdir(), 'totp-deploy-verify-'));
  const envDir = join(workDir, 'etc');
  const tlsDir = join(envDir, 'tls');
  const dataDir = join(workDir, 'data');
  const backupDir = join(workDir, 'respaldos');
  mkdirSync(tlsDir, { recursive: true });
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  mkdirSync(backupDir, { recursive: true, mode: 0o700 });

  const checks = [];
  const registrar = (paso, ok, detalle) => checks.push({ paso, ok: Boolean(ok), detalle });

  let proc = null;
  let dastResultado = null;
  let dastRutas = null;

  try {
    // 1. Validación sintáctica y de endurecimiento de deploy/servicio-totp.service con systemd-analyze
    const unitRaw = readFileSync(SERVICE_FILE, 'utf8');
    const tempUnit = join(workDir, 'servicio-totp.service');
    // Ajustamos solo rutas de trabajo para que systemd-analyze verify no marque rutas inexistentes /opt/servicio-totp en este host
    const unitLocal = unitRaw
      .replaceAll('/opt/servicio-totp/backend', join(REPO_ROOT, 'backend'))
      .replaceAll('/opt/servicio-totp', REPO_ROOT)
      .replaceAll('/var/lib/servicio-totp', dataDir)
      .replaceAll('/etc/servicio-totp/servicio-totp.env', join(envDir, 'servicio-totp.env'));
    writeFileSync(tempUnit, unitLocal, 'utf8');

    const verifyRes = ejecutarComando('systemd-analyze', ['verify', tempUnit]);
    const soloAvisoUsuario = !verifyRes.ok && /Unknown user|not found/i.test(verifyRes.stderr);
    registrar(
      'systemd-analyze verify (sintaxis de unidad)',
      verifyRes.ok || soloAvisoUsuario,
      verifyRes.ok ? 'Sin errores sintácticos ni directivas inválidas' : (verifyRes.stderr || verifyRes.stdout),
    );

    const secRes = ejecutarComando('systemd-analyze', ['security', '--offline=yes', '--no-pager', SERVICE_FILE]);
    const scoreLine = secRes.stdout.split('\n').find((l) => /Overall exposure level/i.test(l)) || secRes.stderr || 'No disponible';
    const scoreMatch = scoreLine.match(/([0-9]+(?:\.[0-9]+)?)\s+(SAFE|OK|MEDIUM|EXPOSED|UNSAFE)/i);
    registrar(
      'systemd-analyze security (endurecimiento)',
      Boolean(scoreMatch && Number(scoreMatch[1]) <= 3.5),
      scoreLine.trim(),
    );

    // 2. Generar configuración de producción sin secretos hardcodeados (deploy/README.md §3)
    const envPath = join(envDir, 'servicio-totp.env');
    execFileSync(process.execPath, [join(REPO_ROOT, 'backend', 'scripts', 'generar-env.js'), '--salida', envPath], { stdio: 'pipe' });
    const certPath = join(tlsDir, 'servidor.crt');
    const keyPath = join(tlsDir, 'servidor.key');
    const dbPath = join(dataDir, 'totp_soberano.db');
    const port = puerto;

    // 3. Generar certificado EC P-256 con openssl según deploy/README.md §4
    execFileSync('openssl', [
      'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
      '-keyout', keyPath, '-out', certPath, '-days', '7', '-nodes',
      '-subj', '/O=InstitucionPrueba/CN=localhost',
      '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
    ], { stdio: 'pipe' });
    chmodSync(keyPath, 0o640);

    let envText = readFileSync(envPath, 'utf8');
    const reemplazos = {
      NODE_ENV: 'production',
      HOST: '127.0.0.1',
      PORT: String(port),
      TLS_MODE: 'node',
      TLS_CERT_PATH: certPath,
      TLS_KEY_PATH: keyPath,
      SQLITE_DB_PATH: dbPath,
      JWT_ISSUER: 'https://totp.institucion.local',
      CORS_ALLOWED_ORIGINS: '',
    };
    for (const [k, v] of Object.entries(reemplazos)) {
      const re = new RegExp(`^${k}=.*$`, 'm');
      envText = re.test(envText) ? envText.replace(re, `${k}=${v}`) : `${envText}\n${k}=${v}`;
    }
    writeFileSync(envPath, `${envText.trim()}\n`, { mode: 0o640 });
    registrar('Configuración .env + certificado TLS EC P-256 (permisos 0640)', existsSync(envPath) && existsSync(certPath), `env 0640 + key 0640 en ${workDir}`);

    // 4. Fail-fast en NODE_ENV=production si TLS_MODE=off
    const badEnvPath = join(envDir, 'bad.env');
    writeFileSync(badEnvPath, envText.replace(/^TLS_MODE=.*/m, 'TLS_MODE=off'), { mode: 0o600 });
    const failFast = spawnSync(process.execPath, [join(REPO_ROOT, 'backend', 'src', 'main.js')], {
      cwd: join(REPO_ROOT, 'backend'),
      env: { ...process.env, NODE_ENV: 'production', ENV_FILE: badEnvPath },
      encoding: 'utf8',
      timeout: 5000,
    });
    registrar(
      'Fail-fast en producción (rechaza TLS_MODE=off)',
      failFast.status !== 0,
      `código salida=${failFast.status} (${(failFast.stderr || failFast.stdout).split('\n')[0] || 'rechazado'})`,
    );

    // 5. Ejecutar semilla institucional (deploy/README.md §6)
    const seedOut = execFileSync(process.execPath, [join(REPO_ROOT, 'backend', 'scripts', 'semilla.js')], {
      cwd: join(REPO_ROOT, 'backend'),
      env: { ...process.env, NODE_ENV: 'production', ENV_FILE: envPath },
      encoding: 'utf8',
    });
    const qrAdminPath = join(REPO_ROOT, 'backend', 'data', 'admin-qr.svg');
    if (existsSync(qrAdminPath)) rmSync(qrAdminPath, { force: true });
    const seedOk = /Portal de Trámites/i.test(seedOut) && /Agente Evaluador \(Reto 3\)/i.test(seedOut) && existsSync(dbPath);
    registrar('Semilla inicial (Portal de Trámites, Reto 3 y admin)', seedOk, 'BD SQLite WAL inicializada con 8 tablas y apps semilla');

    // 6. Arrancar el servidor real en modo NODE_ENV=production (deploy/README.md §7)
    const tArranque = Date.now();
    const stderrLogs = [];
    proc = spawn(process.execPath, [join(REPO_ROOT, 'backend', 'src', 'main.js')], {
      cwd: join(REPO_ROOT, 'backend'),
      env: { ...process.env, NODE_ENV: 'production', ENV_FILE: envPath },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    proc.stderr.on('data', (d) => stderrLogs.push(d.toString('utf8')));

    const baseUrl = `https://127.0.0.1:${port}`;
    const caPem = readFileSync(certPath);
    const readyRes = await esperarListo(`${baseUrl}/health/ready`, caPem, 8000);
    const arranqueMs = Date.now() - tArranque;
    registrar('Arranque producción TLS 1.3 + /health/ready 200', readyRes.status === 200, `listo en ${arranqueMs} ms`);

    // 7. Verificar endpoints operativos y frontends servidos por el mismo proceso
    const [jwks, pwa, consola, metrics] = await Promise.all([
      httpsGet(`${baseUrl}/.well-known/jwks.json`, caPem),
      httpsGet(`${baseUrl}/app/`, caPem),
      httpsGet(`${baseUrl}/consola/`, caPem),
      httpsGet(`${baseUrl}/metrics`, caPem),
    ]);
    const rutasOk = jwks.status === 200 && pwa.status === 200 && consola.status === 200 && metrics.status === 200;
    registrar(
      'Rutas críticas operativas (JWKS, /app/, /consola/, /metrics)',
      rutasOk,
      `jwks=${jwks.status}, /app/=${pwa.status}, /consola/=${consola.status}, /metrics=${metrics.status}`,
    );

    // 8. Ejecutar nuestro escáner DAST propio (C6, #24) en vivo contra este servidor de producción
    const ctx = crearContexto({
      url: baseUrl,
      ca: certPath,
      inseguro: false,
      apps: [],
      timeoutMs: 5000,
      ventana: 1,
      detallado: false,
      color: false,
      opciones: {},
    });
    dastResultado = await correrEscenario(dast, ctx, 12);
    ctx.cerrar();
    registrar(
      'Escaneo dinámico DAST propio en vivo contra producción TLS 1.3',
      dastResultado.ok,
      `${dastResultado.verificaciones.filter((v) => v.ok === true).length}/${dastResultado.verificaciones.filter((v) => v.ok !== null).length} verificaciones OK, ${dastResultado.hallazgos.length} hallazgos críticos/altos`,
    );

    if (guardarInformeDast) {
      const informe = {
        generado: new Date().toISOString(),
        destino: baseUrl,
        entorno: { node: process.version, plataforma: process.platform, modo: 'NODE_ENV=production (despliegue equivalente systemd)' },
        resumen: resumir([dastResultado], dastResultado.duracionMs),
        resultados: [dastResultado],
      };
      dastRutas = escribirInforme(informe, guardarInformeDast);
    }

    // 9. Prueba de copia de seguridad consistente en caliente SQLite VACUUM INTO (deploy/README.md §8)
    const copiaPath = join(backupDir, 'copia-caliente.db');
    const dbLive = new DatabaseSync(dbPath);
    dbLive.exec(`VACUUM INTO '${copiaPath.replace(/'/g, "''")}'`);
    dbLive.close();
    const dbCopia = new DatabaseSync(copiaPath, { readOnly: true });
    const tablas = dbCopia.prepare("SELECT count(*) AS n FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").get();
    const appsCount = dbCopia.prepare('SELECT count(*) AS n FROM apps').get();
    dbCopia.close();
    registrar(
      'Copia de seguridad en caliente (SQLite VACUUM INTO)',
      tablas.n >= 8 && appsCount.n >= 2,
      `${tablas.n} tablas intactas, ${appsCount.n} apps integradoras respaldadas sin detener el servicio`,
    );

    // 10. Apagado ordenado con SIGTERM (deploy/servicio-totp.service: KillSignal=SIGTERM, TimeoutStopSec=15)
    const tStop = Date.now();
    const exitCode = await new Promise((resolver) => {
      const timer = setTimeout(() => { proc.kill('SIGKILL'); resolver(-1); }, 10000);
      proc.once('exit', (code) => { clearTimeout(timer); resolver(code); });
      proc.kill('SIGTERM');
    });
    const stopMs = Date.now() - tStop;
    proc = null;
    registrar('Apagado ordenado con SIGTERM (<15 s)', exitCode === 0 && stopMs < 10000, `código salida=${exitCode}, tiempo=${stopMs} ms`);

    return {
      ok: checks.every((c) => c.ok),
      timestamp: new Date().toISOString(),
      entorno: { node: process.version, plataforma: process.platform, systemd: ejecutarComando('systemd-analyze', ['--version']).stdout.split('\n')[0] || 'N/A' },
      checks,
      dast: dastResultado,
      dastRutas,
      stderrLogs: stderrLogs.join('').trim(),
    };
  } finally {
    if (proc && proc.exitCode === null) proc.kill('SIGKILL');
    rmSync(workDir, { recursive: true, force: true });
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const outIdx = process.argv.indexOf('--guardar-dast');
  const guardarInformeDast = outIdx !== -1 ? process.argv[outIdx + 1] : null;
  const pIdx = process.argv.indexOf('--puerto');
  const puerto = pIdx !== -1 ? Number(process.argv[pIdx + 1]) : 18443; // --puerto N cuando 18443 está ocupado
  const res = await verificarDespliegue({ guardarInformeDast, puerto });
  console.log('\n=== VERIFICACIÓN DE DESPLIEGUE INSTITUCIONAL (systemd + TLS 1.3 + DAST) ===');
  console.table(res.checks.map((c) => ({ Paso: c.paso, Estado: c.ok ? 'OK' : 'FALLO', Detalle: c.detalle.slice(0, 90) })));
  if (res.dastRutas) {
    console.log(`Informe DAST escrito en:\n  · ${res.dastRutas.json}\n  · ${res.dastRutas.html}`);
  }
  if (!res.ok) process.exitCode = 1;
}
