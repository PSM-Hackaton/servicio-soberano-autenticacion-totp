# Preparación de la entrega para el GitLab del evento

`scripts/preparar-entrega.sh` genera una **copia limpia** del proyecto, lista para subir al GitLab del
Hackatón 2026, **sin subir nada**: no añade remotos ni ejecuta `git push`. El repositorio de trabajo
(GitHub interno del equipo) no se modifica en ningún momento.

Requisitos: `sh` POSIX, `git` y Node.js 22 o superior. Sin dependencias externas. Si `pdftotext`
está instalado, también se revisa el texto de los PDF; si no, solo sus bytes.

## Uso

```sh
# Cierre diario: rama avance, desde lo confirmado en HEAD, en ../entrega-gitlab
sh scripts/preparar-entrega.sh

# Desde una rama concreta y a otra carpeta
sh scripts/preparar-entrega.sh --ref staging --salida /ruta/entrega-gitlab

# Entrega final: crea también la rama terminado en el mismo commit
sh scripts/preparar-entrega.sh --ref main --final

# Rehacer una entrega anterior en la misma carpeta
sh scripts/preparar-entrega.sh --forzar
```

| Opción | Efecto |
| :--- | :--- |
| `--ref REF` | Rama, etiqueta o commit a exportar. Por defecto `HEAD`. Los cambios sin commit **no** se incluyen (el script avisa). |
| `--salida DIR` | Carpeta de salida. Por defecto `../entrega-gitlab` respecto a la raíz del repositorio. No puede estar dentro del repositorio. |
| `--final` | Crea también la rama `terminado` apuntando al mismo commit que `avance`. |
| `--forzar` | Borra la carpeta de salida si ya existe, solo si es una entrega anterior (repositorio git con rama `avance`). |
| `--permitidos ARCH` | Lista de hallazgos aceptados a conciencia (ver más abajo). |

El autor del commit se toma de `git config user.name` / `user.email` del repositorio original. Debe ser
una persona del equipo: si no está configurado (o parece una cuenta automática), el script falla.

## Qué hace, paso a paso

1. **Exporta** el árbol de la referencia con `git archive` (sin historial interno, sin ramas, sin `.git`).
2. **Excluye** el material interno según `scripts/exclusiones-entrega.txt`.
3. **Revisa enlaces** relativos y menciones en `*.md` y `*.html`: avisa de enlaces a material excluido y de
   enlaces rotos previos. En la copia corrige `README.md` y `ARCHITECTURE.md` (quita los enlaces o
   menciones a lo excluido) y quita de los `.gitignore` las entradas de carpetas locales de herramientas.
4. **Verifica** la copia; la preparación falla si encuentra:
   - nombres de herramientas o servicios externos de generación de contenido, o líneas de coautoría
     de commits (la lista exacta está en `entrega-herramientas.mjs`), sin distinguir mayúsculas;
   - rutas locales `/home/`;
   - secretos: tokens de GitHub/GitLab y similares, o bloques PEM de llave privada completos (los textos de
     prueba y el código que genera llaves en tiempo de ejecución no cuentan);
   - archivos sensibles por nombre (`.env` reales, llaves, certificados, bases de datos, `node_modules`);
   - archivos de más de 5 MB;
   - un `README.md` sin los 6 apartados del instructivo como títulos `## N. Nombre`, en este orden:
     1 Nombre del proyecto, 2 Participantes, 3 Descripción del proyecto, 4 Alcance,
     5 Requerimientos del sistema, 6 Instalación y despliegue.
5. **Prueba que funciona aislada**, en una copia temporal (la carpeta de salida no se ensucia):
   `cd backend && npm test`; `node --test` con los `tests/*.test.js|mjs` de `authenticator-app`, `sdk`,
   `demo-portal-tramites` y `attack-lab`; e instalación mínima con `node scripts/generar-env.js --salida <temporal>`
   (sin `CHANGE_ME`, permisos 600, llave maestra de 256 bits).
6. **Crea un repositorio git nuevo** en la carpeta de salida: rama `avance` (y `terminado` con `--final`), un único
   commit con el mensaje *«Entrega: Servicio Soberano de Autenticación Multifactorial basado en Tiempo»*, sin
   remotos, sin hooks. Comprueba que todo quedó versionado e imprime los comandos para subirlo.

Si algo falla, la carpeta de salida queda tal cual para inspeccionarla. **Los problemas de contenido se
corrigen en el repositorio de trabajo** (con su commit normal) y se vuelve a preparar la entrega; nunca a
mano en la copia.

## Qué se excluye y por qué

La lista completa y comentada está en `scripts/exclusiones-entrega.txt`. En resumen:

| Excluido | Motivo |
| :--- | :--- |
| `AGENTS.md`, `TASKS.md`, `ANALISIS_FASE0.md`, `SYSTEM_GRAPH.md` | Coordinación interna del equipo (pizarrón, guía de ramas, auditoría inicial, grafo de trabajo). El producto ya se documenta en `README.md`, `ARCHITECTURE.md` y `docs/`. Ningún documento público enlaza al grafo, así que no se genera versión pública. |
| `scripts/preparar-entrega.sh`, `scripts/exclusiones-entrega.txt`, `scripts/entrega-herramientas.mjs`, este archivo | Herramienta interna de preparación. |
| `.claude/`, `.vscode/`, `.idea/` | Carpetas locales de editores y herramientas. |
| `attack-lab/resultados/*` (salvo `.gitkeep`) | Resultados de cada ejecución, con datos de la máquina local. El informe oficial está en `docs/evidencias/`. |
| `.env` y variantes (salvo `.env.example`) | Llaves maestras y peppers reales. Solo se publican las plantillas. |
| `*.db`, `*.sqlite*` y archivos auxiliares | Bases de datos locales con datos de prueba o reales. |
| `*.pem`, `*.key`, `*.crt`, `*.p12`, `certs/`, llaves SSH | Certificados y llaves: se generan en cada instalación. |
| `node_modules/`, `dist/`, `build/`, `coverage/` | Dependencias y artefactos locales (el proyecto no tiene dependencias). |
| `.DS_Store`, `Thumbs.db`, `*.log` | Basura del sistema y registros. |

### Hallazgos aceptados (`--permitidos`)

Si un hallazgo es legítimo (por ejemplo, una ruta ficticia dentro de una prueba), lo correcto es cambiar el
contenido en el repositorio. Solo si no es posible, cree `scripts/permitidos-entrega.txt` (también excluido de
la entrega) con una línea por archivo y categoría, y páselo con `--permitidos`:

```text
# categoría  ruta-en-la-entrega
rutas        attack-lab/tests/utilidades.test.js
```

Categorías: `marcas` (nombres de herramientas o coautoría), `rutas` (`/home/`), `secretos`. Los hallazgos aceptados
se listan igualmente en la salida.

## Subir la entrega (lo hace una persona del equipo, a mano)

Al terminar, el script imprime los comandos exactos. Con la URL del proyecto en el GitLab del evento:

```sh
cd ../entrega-gitlab
git remote add gitlab <URL>
git push gitlab avance
git push gitlab terminado     # solo en la entrega final (--final)
```

### Si GitLab ya tiene historial

El proyecto del evento puede venir con commits (por ejemplo, un README inicial) o con entregas de días
anteriores. En ese caso el push de `avance` será rechazado por historias distintas. **No use `--force`.**
Siga el flujo del instructivo con una rama de trabajo y Merge Request:

```sh
git fetch gitlab
git switch -c trabajo-AAAA-MM-DD gitlab/avance   # parte de lo ya publicado en avance
git read-tree -u --reset avance                  # deja exactamente el contenido de la entrega nueva
git commit -m "Avance del día AAAA-MM-DD"
git push gitlab trabajo-AAAA-MM-DD               # luego, Merge Request hacia avance en GitLab
```

El script deja configurado el autor del equipo en el repositorio de la entrega (`git config user.name/email`
locales), así que estos commits llevan la misma autoría.

## Checklist del instructivo de GitLab

- [ ] Acceso: sesión iniciada con el correo de registro y contraseña temporal cambiada por una robusta (12+ caracteres).
- [ ] Proyecto asignado localizado en el panel de GitLab y su URL a mano.
- [ ] Durante la jornada: commits y pushes frecuentes a la rama de trabajo.
- [ ] **Al final de cada día: Merge Request diario hacia `avance`** (preparar con este script, sin `--final`).
- [ ] **Al terminar el proyecto: Merge Request final hacia `terminado`** (preparar con `--final`).
- [ ] `README.md` en la raíz con los 6 apartados, en orden: 1 Nombre del proyecto · 2 Participantes (nombre completo y rol) ·
      3 Descripción del proyecto · 4 Alcance (funcionalidades y límites) · 5 Requerimientos del sistema (lenguajes,
      versiones, dependencias, servicios, variables de entorno) · 6 Instalación y despliegue (clonar, configurar, ejecutar).
- [ ] La preparación terminó sin errores (verificaciones y pruebas en verde).
- [ ] Revisados los avisos de enlaces rotos de la salida.
- [ ] Autor del commit: persona del equipo; ningún remoto añadido por el script.
