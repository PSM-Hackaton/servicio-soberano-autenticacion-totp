# Preparación y subida de la entrega al GitLab del evento

Herramientas internas (no se publican) para llevar al GitLab del Hackatón 2026 una **copia limpia** del
proyecto, de forma **progresiva**, como pide el instructivo: commits y pushes frecuentes en las ramas de
trabajo durante la jornada, Merge Request diario hacia `avance` y Merge Request final hacia `terminado`.

Flujo del equipo (quién sube qué, aprobación de Diego o Juan, Merge Request, ramas protegidas):
[`docs/entrega/flujo-gitlab.md`](../docs/entrega/flujo-gitlab.md).

GitHub sigue siendo el repositorio de trabajo del equipo (historial completo, revisiones, issues) y **no se
modifica**. A GitLab va solo la versión limpia, sin el material interno de `scripts/exclusiones-entrega.txt`.

| Herramienta | Para qué |
| :--- | :--- |
| `scripts/preparar-entrega.sh` | Copia limpia verificada y probada en **un único commit** (`avance`; `terminado` con `--final`). Sirve para revisar la entrega y para la comprobación final. |
| `scripts/subir-por-etapas.sh` | **Día 1**: reconstruye la copia limpia como **9 commits por etapas** (`scripts/etapas-entrega.txt`), con autor por etapa, en las ramas `diego` y `laya`; prepara `avance`. |
| `scripts/sincronizar-gitlab.sh` | **Día 2 en adelante**: lleva a la copia de entrega los commits nuevos de GitHub, **uno por commit original** (mismo mensaje y autor, hora real). |
| `scripts/entrega-comun.sh` | Funciones compartidas por los tres (exportar, excluir, ajustar, verificar, probar, confirmar y subir). |
| `scripts/entrega-herramientas.mjs` | Apoyo en Node.js: exclusiones, enlaces, verificaciones, reparto en etapas y copia de archivos. |
| `scripts/instalar-hooks.sh`, `scripts/hooks/` | Ganchos de git `pre-commit`, `commit-msg` y `pre-push` con las mismas reglas de `entrega-herramientas.mjs` (ver más abajo). |

Requisitos: `sh` POSIX, `git` y Node.js 22 o superior. Sin dependencias externas. Si `pdftotext` está
instalado, también se revisa el texto de los PDF; si no, solo sus bytes.

**Ningún script añade remotos ni hace `git push` por su cuenta.** Solo con `--subir` muestran cada
`git push gitlab <rama>` y lo ejecutan si se escribe exactamente `SI`; nunca fuerzan un push ni abren
Merge Request. Los commits llevan siempre la hora real.

## Flujo completo

### Antes de empezar (una vez)

1. Configurar la persona que ejecuta en el repositorio de GitHub: `git config user.name "Nombre Apellido"` y
   `git config user.email "correo"` (los scripts fallan si falta o si parece una cuenta automática).
2. Tener la URL del proyecto en GitLab (botón *Clone*) y comprobar qué ramas existen ya (`avance`, `terminado`).
3. Probar sin subir nada: `sh scripts/preparar-entrega.sh --salida /tmp/revision --permitidos scripts/permitidos-entrega.txt`.

### Día 1: poner al día lo ya hecho, por etapas

```sh
# 1) Preparar y revisar (sin --subir no se ejecuta ningún push)
sh scripts/subir-por-etapas.sh --ref diego --salida ../entrega-gitlab \
   --autor-laya "Juan Laya <correo-de-juan>" --permitidos scripts/permitidos-entrega.txt

# 2) Subir de verdad, etapa por etapa (pide SI antes de cada push)
sh scripts/subir-por-etapas.sh --ref diego --salida ../entrega-gitlab --forzar \
   --autor-laya "Juan Laya <correo-de-juan>" --permitidos scripts/permitidos-entrega.txt \
   --subir --remoto <URL-del-proyecto-en-GitLab>
```

Qué hace:

1. Genera la copia limpia completa con las mismas funciones que `preparar-entrega.sh` (exportar con
   `git archive`, excluir, ajustar enlaces, verificar y ejecutar todas las pruebas).
2. Reparte sus archivos en las etapas de `scripts/etapas-entrega.txt`. Falla si un archivo queda sin
   etapa, si una etapa queda vacía, si una ruta no coincide con nada o si se colara algo excluido.
3. Crea un repositorio git nuevo en `--salida` y aplica cada etapa como un commit **acumulativo** (añade sus
   archivos a lo ya subido) con su autor y su mensaje. Antes de cada commit verifica el árbol (rastros,
   rutas `/home/`, secretos, archivos sensibles, tamaño; el README de 6 apartados desde la etapa que lo
   incorpora). Quien confirma (*committer*) es la persona que ejecuta el script.
4. Comprueba que hay 9 commits, que ningún autor o mensaje lleva texto no permitido y que el árbol final es
   **idéntico** a la copia limpia (mismo árbol git que `preparar-entrega.sh`).
5. Prepara la rama local `avance` como merge `--no-ff` de las ramas de trabajo, guarda el estado de
   sincronización e imprime cómo abrir el Merge Request.

**Modelo de ramas.** La historia es **lineal** en la rama local `integracion` (no se sube nunca). Cada commit
mueve además la rama de trabajo de su autor (`diego` o `laya`) hasta él por avance rápido: equivale a que
cada persona actualiza su rama con la del compañero antes de su commit. Así las dos ramas comparten
historia, ningún push necesita forzarse y la rama más adelantada contiene todo.

| Etapa | Autor | Rama | Contenido |
| :--- | :--- | :--- | :--- |
| 1 `estructura` | Diego Landaeta | `diego` | `.gitignore`, `SECURITY.md`, material del reto, análisis técnico |
| 2 `arquitectura` | Juan Laya | `laya` | `ARCHITECTURE.md`, `CONTRIBUTING.md`, `.env.example`, OpenAPI, esquemas SQL y sus respuestas de ejemplo |
| 3 `nucleo` | Diego Landaeta | `diego` | Motor TOTP, bóveda AES-256-GCM, tokens Ed25519, QR propio y pruebas |
| 4 `persistencia` | Diego Landaeta | `diego` | SQLite, seguridad, auditoría encadenada, detector de anomalías y pruebas |
| 5 `servidor` | Diego Landaeta | `diego` | Casos de uso, servidor HTTPS, arranque, scripts y resto de respuestas de ejemplo |
| 6 `aplicaciones` | Diego Landaeta | `diego` | App autenticadora, consola, SDK, Portal de Trámites, guía de integración y manual |
| 7 `laboratorio-despliegue` | Diego Landaeta | `diego` | Laboratorio de ataques y caos, su informe, despliegue como servicio y respaldos |
| 8 `verificacion` | Juan Laya | `laya` | Escaneo dinámico (DAST), verificación del despliegue, sus evidencias, SBOM, guion de demo, guía del Reto 1 |
| 9 `documentacion` | Diego Landaeta | `diego` | README de 6 apartados, licencia, matriz de cumplimiento, escalabilidad y presentación |

El reparto sigue la autoría real (`git log --format=%an -- <ruta>`): cuando una parte mezcla autores, cada
archivo va a la etapa de quien lo creó o lo dejó en su forma actual. Por eso los temas del issue #55 se
agrupan así: el escaneo dinámico y la verificación del despliegue (de Juan) forman su propia etapa 8, y el
despliegue (de Diego) se sube junto al laboratorio en la 7. Para cambiar el plan, edite
`scripts/etapas-entrega.txt` (formato explicado en su cabecera) y vuelva a ejecutar sin `--subir`.

**Cierre del día 1** (en la web de GitLab; el script no lo hace):

1. Si `avance` no existe en GitLab, crearla desde el primer commit (el script imprime el comando exacto,
   `git push gitlab <commit-etapa-1>:refs/heads/avance`).
2. *Code > Merge requests > New merge request*: origen `diego` (la rama más adelantada, que contiene también
   las etapas de `laya`), destino `avance`. Sin *Squash commits*, para no perder el historial por etapas.
3. Comparar el diff con la rama local `avance` (es el resultado esperado) y hacer el merge.

### Día 2 en adelante: subida continua

Cada tarea que se cierra en GitHub (issue resuelto y pruebas en verde) se sube en el momento a la rama de
trabajo de quien la hizo:

```sh
# Ver qué se subiría (no cambia nada)
sh scripts/sincronizar-gitlab.sh --entrega ../entrega-gitlab --hasta diego --plan

# Sincronizar y subir (pide SI antes de cada push; el remoto gitlab ya está en la copia de entrega)
sh scripts/sincronizar-gitlab.sh --entrega ../entrega-gitlab --hasta diego \
   --permitidos scripts/permitidos-entrega.txt --subir
```

- **Desde dónde**: por defecto, el último commit sincronizado, guardado en
  `../entrega-gitlab/.git/entrega-sincronizacion` (dentro de `.git` de la copia de entrega: nunca se versiona
  ni llega a GitHub o GitLab). Se puede forzar con `--desde <ref>`.
- **Qué comprueba primero**: que la copia de entrega está en `integracion`, sin cambios, y que su contenido es
  exactamente la versión limpia de `--desde`.
- **Un commit por commit original**, recorriendo la historia principal de GitHub (primer padre) del más antiguo
  al más reciente: un commit normal deja la entrega igual a su versión limpia; un merge (p. ej. «Integrar la
  rama laya») aplica primero, uno por uno, los commits de la rama integrada con su autor, y después el merge
  si añade algo más. Si un commit de la rama integrada no se puede aplicar por separado, se avisa y sus
  cambios llegan con el del merge. Los commits que solo tocan material excluido no generan commit.
- **Antes de cada commit**: verificaciones completas (incluido el README) y todas las pruebas; si algo falla,
  se deshace el cambio y no se confirma nada.
- **Autor y rama**: el del commit original (sin líneas de coautoría). Cada commit va a la rama de su autor según
  su nombre o correo: `laya`/`lya0509` → `laya`; `javier`/`jarviscott` → `javier`; `enggel`/`metagamingprohd` →
  `enggel`; `giovani` → `giovani`; el resto, a `diego`. Quien ejecuta con `--subir` responde `SI` solo al push
  de su propia rama. `--autor-laya "Nombre <correo>"` firma los
  de Juan con su nombre completo.
- Al final comprueba que la entrega coincide con la versión limpia de `--hasta` y guarda el estado.

Cierre de cada día: Merge Request de la rama más adelantada hacia `avance`, como el día 1.
**Code freeze** 4 horas antes de la entrega (regla de `CONTRIBUTING.md`).

### Entrega final

1. Tras el code freeze, última sincronización y Merge Request diario hacia `avance`.
2. Comprobar la versión final con `sh scripts/preparar-entrega.sh --ref <rama-final> --final --salida /tmp/final
   --permitidos scripts/permitidos-entrega.txt`: debe terminar sin errores y su árbol debe coincidir con el de
   la copia de entrega (`git -C ../entrega-gitlab rev-parse integracion^{tree}` frente a
   `git -C /tmp/final rev-parse avance^{tree}`).
3. En GitLab: Merge Request de `avance` hacia `terminado` (si `terminado` no existe, crearla desde `avance`
   antes, con `git push gitlab <commit>:refs/heads/terminado`).

## `preparar-entrega.sh`: copia limpia en un solo commit

```sh
sh scripts/preparar-entrega.sh                                   # HEAD, rama avance, en ../entrega-gitlab
sh scripts/preparar-entrega.sh --ref staging --salida /ruta/x    # otra referencia y carpeta
sh scripts/preparar-entrega.sh --ref main --final                # también rama terminado
sh scripts/preparar-entrega.sh --forzar                          # rehacer una entrega anterior
sh scripts/preparar-entrega.sh --sin-repositorio --salida /ruta  # solo la copia verificada y probada
```

| Opción | Efecto |
| :--- | :--- |
| `--ref REF` | Rama, etiqueta o commit a exportar. Por defecto `HEAD`. Los cambios sin commit **no** se incluyen (el script avisa). |
| `--salida DIR` | Carpeta de salida. Por defecto `../entrega-gitlab` respecto a la raíz del repositorio. No puede estar dentro del repositorio. |
| `--final` | Crea también la rama `terminado` apuntando al mismo commit que `avance`. |
| `--forzar` | Borra la carpeta de salida si ya existe, solo si es una entrega anterior (repositorio git con rama `avance`). |
| `--permitidos ARCH` | Lista de hallazgos aceptados a conciencia (ver más abajo). |
| `--sin-repositorio` | Se detiene tras verificar y probar: deja solo la copia limpia, sin repositorio git. |

Pasos (los mismos que usan los otros dos scripts, desde `entrega-comun.sh`):

1. **Exporta** el árbol de la referencia con `git archive` (sin historial interno, sin ramas, sin `.git`).
2. **Excluye** el material interno según `scripts/exclusiones-entrega.txt`.
3. **Revisa enlaces** relativos y menciones en `*.md` y `*.html`: avisa de enlaces a material excluido y de
   enlaces rotos previos. En la copia corrige `README.md` y `ARCHITECTURE.md` (quita los enlaces o
   menciones a lo excluido) y quita de los `.gitignore` las entradas de carpetas locales de herramientas.
4. **Verifica** la copia; falla si encuentra:
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
5. **Prueba que funciona aislada**, en una copia temporal: `cd backend && npm test`; `node --test` con los
   `tests/*.test.js|mjs` de `authenticator-app`, `sdk`, `demo-portal-tramites` y `attack-lab`; e instalación
   mínima con `node scripts/generar-env.js --salida <temporal>` (sin `CHANGE_ME`, permisos 600, llave de 256 bits).
6. **Crea un repositorio git nuevo** en la carpeta de salida: rama `avance` (y `terminado` con `--final`), un único
   commit *«Entrega: Servicio Soberano de Autenticación Multifactorial basado en Tiempo»*, sin remotos, sin hooks.

Si algo falla, la carpeta de salida queda tal cual para inspeccionarla. **Los problemas de contenido se
corrigen en el repositorio de trabajo** (con su commit normal) y se vuelve a preparar; nunca a mano en la copia.

### Si GitLab ya tiene historial

Si el proyecto del evento trae commits propios (p. ej. un README inicial) en la rama a la que se sube, el push
será rechazado por historias distintas. **No use `--force`.** Opciones:

- Para la subida por etapas, empujar a ramas de trabajo nuevas (`diego`, `laya`) y unirlas a `avance` por Merge
  Request (GitLab permite el merge si no hay conflictos; si los hay, resolverlos en el propio Merge Request).
- Para la copia de un solo commit:

```sh
git fetch gitlab
git switch -c trabajo-AAAA-MM-DD gitlab/avance   # parte de lo ya publicado en avance
git read-tree -u --reset avance                  # deja exactamente el contenido de la entrega nueva
git commit -m "Avance del día AAAA-MM-DD"
git push gitlab trabajo-AAAA-MM-DD               # luego, Merge Request hacia avance en GitLab
```

## Qué se excluye y por qué

La lista completa y comentada está en `scripts/exclusiones-entrega.txt`. En resumen:

| Excluido | Motivo |
| :--- | :--- |
| `AGENTS.md`, `TASKS.md`, `ANALISIS_FASE0.md`, `SYSTEM_GRAPH.md` | Coordinación interna del equipo (pizarrón, guía de ramas, auditoría inicial, grafo de trabajo). El producto ya se documenta en `README.md`, `ARCHITECTURE.md` y `docs/`. |
| `scripts/preparar-entrega.sh`, `subir-por-etapas.sh`, `sincronizar-gitlab.sh`, `entrega-comun.sh`, `entrega-herramientas.mjs`, `exclusiones-entrega.txt`, `etapas-entrega.txt`, `permitidos-entrega.txt`, `instalar-hooks.sh`, `hooks/`, este archivo | Herramientas internas de preparación, verificación y subida. |
| `.claude/`, `.vscode/`, `.idea/` | Carpetas locales de editores y herramientas. |
| `attack-lab/resultados/*` (salvo `.gitkeep`) | Resultados de cada ejecución, con datos de la máquina local. El informe oficial está en `docs/evidencias/`. |
| `.env` y variantes (salvo `.env.example`) | Llaves maestras y peppers reales. Solo se publican las plantillas. |
| `*.db`, `*.sqlite*` y archivos auxiliares | Bases de datos locales. |
| `*.pem`, `*.key`, `*.crt`, `*.p12`, `certs/`, llaves SSH | Certificados y llaves: se generan en cada instalación. |
| `node_modules/`, `dist/`, `build/`, `coverage/` | Dependencias y artefactos locales (el proyecto no tiene dependencias). |
| `.DS_Store`, `Thumbs.db`, `*.log` | Basura del sistema y registros. |

### Hallazgos aceptados (`--permitidos`)

Si un hallazgo es legítimo, lo correcto es cambiar el contenido en el repositorio. Solo si no es posible, se
anota en `scripts/permitidos-entrega.txt` (excluido de la entrega) con una línea por archivo y categoría, y se
pasa con `--permitidos` (los tres scripts lo aceptan):

```text
# categoría  ruta-en-la-entrega
rutas        deploy/instalar.sh
```

Categorías: `marcas` (nombres de herramientas o coautoría), `rutas` (`/home/`), `secretos`. Los hallazgos
aceptados se listan igualmente en la salida. Hoy la lista contiene solo `deploy/instalar.sh`, cuyo
`case "$NODE" in /root/*|/home/*)` es una comprobación del instalador, no una ruta local.

## Ganchos de git (`scripts/hooks/`)

```sh
sh scripts/instalar-hooks.sh                              # este repositorio (core.hooksPath=scripts/hooks)
sh scripts/instalar-hooks.sh --repo ../entrega-gitlab     # copia de la entrega (ruta absoluta a estos ganchos)
sh scripts/instalar-hooks.sh --quitar [--repo DIR]        # desinstalar
```

Idempotente. La lógica está en `scripts/hooks/revisar.mjs`, que importa las reglas de `entrega-herramientas.mjs`
(`revisarArchivo`, la lista de cadenas prohibidas, exclusiones y permitidos): no hay una segunda copia.

| Gancho | Qué revisa | Bloquea |
| :--- | :--- | :--- |
| `pre-commit` | Solo lo preparado (`git add`), leído del índice | `.env` reales, llaves, certificados, bases `.db`, `node_modules`, archivos de más de 5 MB, secretos; rutas `/home/` y cadenas prohibidas salvo en material interno (`exclusiones-entrega.txt`) y `.gitignore`; respeta `permitidos-entrega.txt` |
| `commit-msg` | El mensaje (sin comentarios de git) | Inglés, título de menos de 10 o más de 100 caracteres, coautorías y menciones. Avisa (sin bloquear) si falta `tipo:`, el `#issue` o la línea en blanco, o si el título pasa de 72 |
| `pre-push` | Autor, quien confirma y mensaje de cada commit nuevo; después `node scripts/verificar-todo.js` | Coautorías, menciones, autores `[bot]`; verificación en rojo. Restaura `docs/sbom/` si la verificación solo lo regeneró |

Emergencias: `SALTAR_VERIFICACION=1 git push …` omite solo `verificar-todo.js` (con visto bueno de Diego o Juan y
anotado en el Merge Request). Los commits de los scripts de entrega usan `--no-verify` porque ya verifican y
prueban cada árbol antes de confirmarlo.

## Pruebas de los scripts sin GitLab

Para probar `--subir` sin tocar GitLab se usa un remoto falso local y se responde `SI` por la entrada estándar
(los scripts leen la confirmación de ahí):

```sh
git init --bare /tmp/gitlab-falso.git
yes SI | sh scripts/subir-por-etapas.sh --ref diego --salida /tmp/entrega-prueba \
   --autor-laya "Juan Laya <correo>" --permitidos scripts/permitidos-entrega.txt \
   --subir --remoto /tmp/gitlab-falso.git
yes SI | sh scripts/sincronizar-gitlab.sh --entrega /tmp/entrega-prueba --hasta diego \
   --permitidos scripts/permitidos-entrega.txt --subir
git -C /tmp/gitlab-falso.git for-each-ref refs/heads    # ramas "subidas"
```

Cualquier respuesta distinta de `SI` (o el fin de la entrada) omite ese push y el script continúa; el
siguiente push de la misma rama incluye lo omitido.

## Lista de comprobación del instructivo de GitLab

- [ ] Acceso: sesión iniciada con el correo de registro; contraseña temporal (inicial del 1.er nombre + inicial del
      2.º nombre + cédula + `hackathon2026`) cambiada por una robusta (12+ caracteres, mayúsculas, minúsculas,
      números y símbolos).
- [ ] Proyecto asignado localizado en el panel de GitLab y su URL a mano; cada persona sube con su propia cuenta.
- [ ] Ramas: `diego`, `laya`, `javier`, `enggel`, `giovani` (trabajo), `avance` (merge diario), `terminado` (merge final),
      protegidas como indica `docs/entrega/flujo-gitlab.md`. Comprobar cuáles existen ya.
- [ ] Ganchos instalados (`sh scripts/instalar-hooks.sh`, también con `--repo ../entrega-gitlab`).
- [ ] Día 1: `subir-por-etapas.sh` sin `--subir`, revisión del plan y del historial; después con `--subir`.
- [ ] Durante la jornada: commits y pushes frecuentes a la rama de trabajo (`sincronizar-gitlab.sh --subir` al cerrar cada tarea).
- [ ] **Al final de cada día: Merge Request hacia `avance`** desde la rama más adelantada, sin *Squash commits*.
- [ ] Code freeze 4 horas antes de la entrega.
- [ ] **Al terminar el proyecto: Merge Request final de `avance` hacia `terminado`.**
- [ ] `README.md` en la raíz **antes del merge a `terminado`**, con los 6 apartados, en orden: 1 Nombre del proyecto ·
      2 Participantes (nombre completo y rol) · 3 Descripción del proyecto · 4 Alcance (funcionalidades y límites) ·
      5 Requerimientos del sistema (lenguajes, versiones, dependencias, servicios, variables de entorno) ·
      6 Instalación y despliegue (clonar, configurar, ejecutar).
- [ ] Verificaciones y pruebas en verde en cada preparación; avisos de enlaces revisados.
- [ ] Autores de los commits: personas del equipo; hora real; ningún `--force`.
