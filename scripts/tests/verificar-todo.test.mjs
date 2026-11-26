// Pruebas de la verificación del README con los títulos de la plantilla del GitLab del evento
// (scripts/verificar-todo.js, paso 5). Ejecutar: node --test 'scripts/tests/*.test.mjs'
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verificarReadmePlantilla, TITULOS_PLANTILLA_README } from '../verificar-todo.js';

const RAIZ = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

// Plantilla tal como la publica el GitLab del evento en la rama desarrollo.
const PLANTILLA = `# reto_otp

## Participantes

- Diego Landaeta

## Descripción del proyecto

## Alcance

## Requerimientos del sistema

## Paso a paso de instalación / despliegue
`;

const conTitulos = (titulos, extra = '') => `# Proyecto\n\n${titulos.map((t) => `## ${t}\n\ntexto\n`).join('\n')}${extra}`;

test('los títulos exigidos son exactamente los de la plantilla, en orden', () => {
  assert.deepEqual(TITULOS_PLANTILLA_README, [
    'Participantes',
    'Descripción del proyecto',
    'Alcance',
    'Requerimientos del sistema',
    'Paso a paso de instalación / despliegue',
  ]);
});

test('la plantilla del evento cumple', () => {
  assert.deepEqual(verificarReadmePlantilla(PLANTILLA), { ok: true, errores: [] });
});

test('el README.md del repositorio cumple', () => {
  const r = verificarReadmePlantilla(readFileSync(join(RAIZ, 'README.md'), 'utf8'));
  assert.deepEqual(r.errores, []);
});

test('admite subapartados ### y comentarios "#" dentro de bloques de código', () => {
  const texto = conTitulos(TITULOS_PLANTILLA_README, '\n### 1. Clonar\n\n```sh\n# comentario\n## tampoco cuenta\n```\n~~~\n# otro\n~~~\n');
  assert.equal(verificarReadmePlantilla(texto).ok, true);
});

test('rechaza los títulos numerados del formato anterior', () => {
  const r = verificarReadmePlantilla(`# P\n\n## 1. Nombre del proyecto\n\n## 2. Participantes\n\n## 3. Descripción del proyecto\n\n## 4. Alcance\n\n## 5. Requerimientos del sistema\n\n## 6. Instalación y despliegue\n`);
  assert.equal(r.ok, false);
  assert.match(r.errores.join('\n'), /"## 1\. Nombre del proyecto" sobra/);
  assert.match(r.errores.join('\n'), /"## 2\. Participantes" debe ser exactamente "## Participantes"/);
  assert.match(r.errores.join('\n'), /"## 6\. Instalación y despliegue" debe ser exactamente "## Paso a paso de instalación \/ despliegue"/);
});

test('rechaza un cambio de texto, aunque sea solo de acentos o mayúsculas', () => {
  const titulos = [...TITULOS_PLANTILLA_README];
  titulos[1] = 'Descripcion del Proyecto';
  const r = verificarReadmePlantilla(conTitulos(titulos));
  assert.equal(r.ok, false);
  assert.match(r.errores[0], /debe ser exactamente "## Descripción del proyecto"/);
});

test('rechaza títulos fuera de orden, repetidos o que faltan', () => {
  const desordenado = [TITULOS_PLANTILLA_README[0], TITULOS_PLANTILLA_README[2], TITULOS_PLANTILLA_README[1],
    TITULOS_PLANTILLA_README[3], TITULOS_PLANTILLA_README[4]];
  const r1 = verificarReadmePlantilla(conTitulos(desordenado));
  assert.equal(r1.ok, false);
  assert.match(r1.errores.join('\n'), /fuera del orden/);

  const r2 = verificarReadmePlantilla(conTitulos(TITULOS_PLANTILLA_README.slice(0, 4)));
  assert.deepEqual(r2.errores, ['Falta el título "## Paso a paso de instalación / despliegue".']);

  const r3 = verificarReadmePlantilla(conTitulos([...TITULOS_PLANTILLA_README, 'Alcance']));
  assert.match(r3.errores.join('\n'), /repetido o fuera del orden/);
});

test('rechaza títulos de nivel 2 que no son de la plantilla', () => {
  const r = verificarReadmePlantilla(conTitulos(TITULOS_PLANTILLA_README, '\n## Licencia\n'));
  assert.equal(r.ok, false);
  assert.match(r.errores[0], /"## Licencia" no es un título de la plantilla/);
});

test('exige un único "# <título>" y que sea el primero', () => {
  const sinTitulo = conTitulos(TITULOS_PLANTILLA_README).replace(/^# Proyecto\n/, '');
  assert.match(verificarReadmePlantilla(sinTitulo).errores.join('\n'), /Falta el título "# <nombre del proyecto>"/);
  const dos = conTitulos(TITULOS_PLANTILLA_README, '\n# Otro\n');
  assert.match(verificarReadmePlantilla(dos).errores.join('\n'), /solo puede haber un título "#"/);
});
