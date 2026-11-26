#!/usr/bin/env node
// Genera datos/usuarios.json con ciudadanos FICTICIOS para la demo (contraseñas con scrypt).
// Uso: node scripts/crear-usuarios.js [--archivo ruta] [--aleatorias]
//   --aleatorias  genera contraseñas aleatorias y las muestra una sola vez.
// Volver a ejecutarlo reinicia el estado: todos los usuarios quedan sin segundo factor.

import { randomBytes } from 'node:crypto';
import { resolve } from 'node:path';
import { generarUsuarios, USUARIOS_DEMO } from '../src/usuarios.js';
import { RAIZ } from '../src/config.js';

const i = process.argv.indexOf('--archivo');
const archivo = i > 0 ? resolve(process.argv[i + 1]) : resolve(RAIZ, 'datos/usuarios.json');
const aleatorias = process.argv.includes('--aleatorias');

const lista = USUARIOS_DEMO.map((u) => ({
  ...u, contrasena: aleatorias ? randomBytes(9).toString('base64url') : u.contrasena,
}));
await generarUsuarios(archivo, lista);

process.stdout.write(`Usuarios demo creados en ${archivo}\n`);
for (const u of lista) process.stdout.write(`  ${u.usuario.padEnd(14)} ${u.contrasena}   (${u.nombre}, ficticio)\n`);
process.stdout.write('Todos empiezan sin segundo factor: el primer ingreso los lleva al enrolamiento.\n');
