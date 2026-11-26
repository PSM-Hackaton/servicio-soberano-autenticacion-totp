#!/usr/bin/env node
// Generador propio de capturas de pantallas en claro/oscuro y móvil/escritorio (Issue #51 · F4).
// Cero dependencias npm: usa Chromium headless del sistema + Node.js 22 nativo.
//
// Uso:
//   node scripts/capturas.js [--salida docs/evidencias/capturas]

import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { iniciar } from '../backend/src/main.js';
import { cargarConfig } from '../backend/src/infrastructure/config/config.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const RAIZ = resolve(__dirname, '..');

function detectarChromium() {
  for (const bin of ['chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable']) {
    const r = spawnSync('which', [bin], { encoding: 'utf8' });
    if (r.status === 0 && r.stdout.trim()) return r.stdout.trim();
  }
  return null;
}

const VISTAS = [
  { nombre: 'pwa-app', ruta: '/app/' },
  { nombre: 'consola-admin', ruta: '/consola/' },
];

const PERFILES = [
  { etiqueta: 'escritorio-claro', ancho: 1280, alto: 800, oscuro: false },
  { etiqueta: 'escritorio-oscuro', ancho: 1280, alto: 800, oscuro: true },
  { etiqueta: 'movil-claro', ancho: 390, alto: 844, oscuro: false },
  { etiqueta: 'movil-oscuro', ancho: 390, alto: 844, oscuro: true },
];

async function main() {
  const idxSalida = process.argv.indexOf('--salida');
  const salidaDir = resolve(RAIZ, idxSalida !== -1 ? process.argv[idxSalida + 1] : 'docs/evidencias/capturas');
  mkdirSync(salidaDir, { recursive: true });

  const chromium = detectarChromium();
  if (!chromium) {
    console.error('No se encontró Chromium/Chrome instalado en el sistema.');
    process.exitCode = 1;
    return;
  }

  const workDir = mkdtempSync(join(tmpdir(), 'totp-capturas-'));
  const envPath = join(workDir, 'demo.env');
  const dbPath = join(workDir, 'capturas.db');
  execFileSync(process.execPath, [join(RAIZ, 'backend', 'scripts', 'generar-env.js'), '--salida', envPath], { stdio: 'pipe' });

  let envTxt = readFileSync(envPath, 'utf8');
  const ajustes = {
    NODE_ENV: 'development',
    HOST: '127.0.0.1',
    PORT: '0',
    TLS_MODE: 'off',
    SQLITE_DB_PATH: dbPath,
    HEURISTICS_MODE: 'mock',
  };
  for (const [k, v] of Object.entries(ajustes)) {
    const re = new RegExp(`^${k}=.*$`, 'm');
    envTxt = re.test(envTxt) ? envTxt.replace(re, `${k}=${v}`) : `${envTxt}\n${k}=${v}`;
  }
  writeFileSync(envPath, `${envTxt.trim()}\n`, 'utf8');

  const config = cargarConfig({ env: { ENV_FILE: envPath, NODE_ENV: 'development' } });
  const app = await iniciar({ config, senales: false });
  const baseUrl = `http://127.0.0.1:${app.puerto}`;
  const generadas = [];

  try {
    for (const vista of VISTAS) {
      for (const perfil of PERFILES) {
        const archivo = join(salidaDir, `${vista.nombre}-${perfil.etiqueta}.png`);
        const args = [
          '--headless=new',
          '--disable-gpu',
          '--no-sandbox',
          '--hide-scrollbars',
          `--window-size=${perfil.ancho},${perfil.alto}`,
          ...(perfil.oscuro ? ['--force-dark-mode', '--enable-features=WebUIDarkMode'] : []),
          `--screenshot=${archivo}`,
          `${baseUrl}${vista.ruta}`,
        ];
        const r = spawnSync(chromium, args, { encoding: 'utf8', timeout: 25_000 });
        if (r.status === 0 && existsSync(archivo)) {
          generadas.push(archivo);
          console.log(`OK: ${vista.nombre}-${perfil.etiqueta}.png`);
        } else {
          console.warn(`AVISO (${vista.nombre}-${perfil.etiqueta}): ${(r.stderr || '').split('\n')[0]}`);
        }
      }
    }
    console.log(`\nCapturas generadas: ${generadas.length}/${VISTAS.length * PERFILES.length} en ${salidaDir}`);
  } finally {
    await app.detener('capturas completadas');
    rmSync(workDir, { recursive: true, force: true });
  }
}

main().catch((e) => {
  console.error(e.message);
  process.exitCode = 1;
});
