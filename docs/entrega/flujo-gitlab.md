# Flujo de trabajo con GitLab del evento

Servicio Soberano de Autenticación TOTP · Hackatón 2026 · Reto Grupal 1 · Responsables: Diego Landaeta y Juan Laya

Cómo cumple el equipo el *Instructivo de uso de GitLab* (subida progresiva por ramas, Merge Request diario a
`avance` y final a `terminado`, `README.md` de 6 apartados) y el requisito de **control de versiones
transparente** de los Términos de Referencia, con autoría real de cada integrante.

## 1. Regla de oro

**Nada llega a GitLab sin la aprobación de Diego Landaeta o Juan Laya.**

| Quién | Qué hace |
| :--- | :--- |
| Diego Landaeta y Juan Laya (Maintainers) | Crean y asignan los issues, revisan, corrigen y aprueban los Pull Request en GitHub; fusionan los Merge Request hacia `avance` y `terminado`. |
| Javier Rodríguez, Enggel Rodríguez, Giovani Marcano (Developers) | Trabajan su issue en su rama, abren el Pull Request en GitHub y, **solo cuando está aprobado**, suben ese trabajo a su rama de GitLab con su propia cuenta. |

- **GitHub** es el repositorio interno de trabajo: historial completo, issues, Pull Request y revisiones. Sus ramas
  `staging` y `main` están protegidas y el archivo `.github/CODEOWNERS` exige la aprobación de Diego o Juan.
- **GitLab** es el repositorio de la entrega: recibe solo la versión limpia del trabajo ya aprobado (sin el
  material interno de `scripts/exclusiones-entrega.txt`), commit a commit, con el autor original.

## 2. Ramas

| Rama en GitLab | Dueño (cuenta de GitHub) | Quién sube | Quién fusiona |
| :--- | :--- | :--- | :--- |
| `diego` | Diego Landaeta (`diego-landaeta`) | Diego | — |
| `laya` | Juan Laya (`lya0509`) | Juan | — |
| `javier` | Javier Rodríguez (`JarviScott`) | Javier | — |
| `enggel` | Enggel Rodríguez (`metagamingprohd-lang`) | Enggel | — |
| `giovani` | Giovani Marcano (`Giovani2011`) | Giovani | — |
| `avance` | Equipo | nadie (solo por Merge Request) | Diego o Juan, al final de cada día |
| `terminado` | Equipo | nadie (solo por Merge Request) | Diego o Juan, una vez, tras el code freeze |

Cada quien sube con **su propia cuenta** de GitLab (la del correo de registro, con la contraseña temporal ya
cambiada por una robusta). Una rama personal solo se crea cuando su dueño tiene trabajo aprobado que subir.

## 3. Ciclo de una tarea

1. **Issue.** Diego o Juan crean el issue en GitHub y lo asignan.
2. **Trabajo en la rama personal de GitHub**, con commits pequeños y frecuentes (apartado 4) y los ganchos
   instalados (apartado 7).
3. **Pull Request en GitHub hacia `staging`**, con el issue enlazado (`Closes #N`). Diego o Juan revisan,
   piden o hacen correcciones y lo aprueban; la protección de rama impide fusionar sin esa aprobación.
4. **Subida a GitLab, solo tras la aprobación y la fusión en `staging`.** El dueño del trabajo lo sube a su rama
   de GitLab con su cuenta, mediante su copia local de la entrega:

   ```sh
   git fetch origin
   sh scripts/sincronizar-gitlab.sh --entrega ../entrega-gitlab --hasta origin/staging --plan   # revisar
   sh scripts/sincronizar-gitlab.sh --entrega ../entrega-gitlab --hasta origin/staging \
      --permitidos scripts/permitidos-entrega.txt --subir                                       # subir
   ```

   El script crea en la copia limpia un commit por cada commit original aprobado (mismo autor y mensaje, hora
   real), verifica y prueba cada uno, y pone cada commit en la rama de su autor (`diego`, `laya`, `javier`,
   `enggel` o `giovani`). Pide escribir `SI` antes de cada `git push gitlab <rama>`: **cada persona responde
   `SI` solo para su propia rama**. Nunca fuerza un push.
5. **Cierre del día.** Diego o Juan abren y fusionan el Merge Request hacia `avance` (apartado 5).

Primera vez en cada computador (copia local de la entrega a partir de lo ya publicado en GitLab):

```sh
git clone <URL-del-proyecto-en-GitLab> ../entrega-gitlab
git -C ../entrega-gitlab remote rename origin gitlab
git -C ../entrega-gitlab switch -c integracion gitlab/avance
sh scripts/sincronizar-gitlab.sh --entrega ../entrega-gitlab --desde <commit-GitHub-ya-en-avance> --plan
```

`--desde` es el último commit de GitHub ya publicado en `avance` (lo indican Diego o Juan). El script comprueba
que la copia coincide exactamente con su versión limpia; si no, se detiene.
El detalle de las herramientas de subida está en `scripts/README-entrega.md`.

## 4. Commits

- **Pequeños y frecuentes durante la jornada**: un commit por cambio con sentido propio (una función y su prueba,
  una pantalla, un documento), subidos a lo largo del día. Nunca un único push gigante al final.
- **Formato** del mensaje, en castellano y en infinitivo:

  ```text
  tipo(ámbito): descripción breve (#N)

  Cuerpo opcional: qué cambia y por qué, en líneas de hasta 72 caracteres.
  ```

  Tipos: `feat`, `fix`, `docs`, `test`, `refactor`, `ci`, `chore`. Ejemplos:
  `feat(backend): añadir ventana de deriva configurable (#12)` ·
  `fix(pwa): corregir el contraste del botón de copiar (#48)` · `docs: actualizar el apartado 6 del README (#55)`.
- **Prohibido**: mensajes en inglés, líneas de coautoría o menciones a herramientas de generación de contenido,
  autores genéricos o automáticos, `git push --force`, `.env` reales, llaves, certificados, bases de datos.
- **Autoría real**: `git config user.name "Nombre Apellido"` y `git config user.email` con el correo propio.

## 5. Merge Request

**Diario, hacia `avance`** (al final de cada día): origen, la rama personal más adelantada del día (las ramas
comparten historia, así que contiene también lo de los demás); destino, `avance`. Descripción: plantilla
**Entrega** (`.gitlab/merge_request_templates/Entrega.md`), con su lista de comprobación y el enlace a cada
Pull Request aprobado en GitHub. Lo revisa y fusiona **Diego o Juan**, sin *Squash commits*.

**Final, hacia `terminado`**: tras el **code freeze** (4 horas antes de la entrega) y el último Merge Request
diario, Merge Request de `avance` hacia `terminado`, con la misma plantilla. Antes se comprueba que `README.md`
tiene los 6 apartados y que `node scripts/verificar-todo.js` está en verde. Lo fusiona Diego o Juan.

## 6. Configuración del proyecto en GitLab (la hacen Diego o Juan)

1. **Miembros** (*Manage › Members*): Diego Landaeta y Juan Laya como **Maintainer**; Javier, Enggel y Giovani como
   **Developer**.
2. **Ramas protegidas** (*Settings › Repository › Protected branches*):

   | Rama | Allowed to merge | Allowed to push and merge | Allowed to force push |
   | :--- | :--- | :--- | :--- |
   | `avance` | Maintainers | No one | No |
   | `terminado` | Maintainers | No one | No |
   | `diego`, `laya`, `javier`, `enggel`, `giovani` | Maintainers | Su dueño (ver nota) | No |

   Nota: elegir **usuarios concretos** en *Allowed to push* (para que solo el dueño suba a su rama) requiere un
   plan de pago de GitLab. En la edición gratuita se protegen las ramas personales con *Allowed to push and
   merge: Developers + Maintainers* y sin *force push*, y la propiedad se controla en la revisión: el autor de cada commit queda a la vista en el
   Merge Request.
3. **Merge requests** (*Settings › Merge requests*): método *Merge commit*; *Squash commits*: *Do not allow*;
   activar *All threads must be resolved*; activar *Pipelines must succeed* solo si el evento ofrece runners.
4. **Aprobación obligatoria.** Las reglas de aprobación obligatoria (número mínimo de aprobaciones, aprobadores
   elegibles, aprobación de *Code Owners*) **pueden requerir un plan de pago**. Si no están disponibles, la
   garantía es doble: solo los Maintainers (Diego y Juan) pueden fusionar en `avance` y `terminado`, y la revisión
   se **registra en el propio Merge Request** (botón *Approve*, casillas del aprobador de la plantilla y comentario
   con nombre, fecha y hora).

## 7. Verificación automática

- **Ganchos de git** (una vez por clon, en GitHub y en la copia de la entrega):

  ```sh
  sh scripts/instalar-hooks.sh                              # repositorio de trabajo
  sh scripts/instalar-hooks.sh --repo ../entrega-gitlab     # copia de la entrega
  ```

  `pre-commit` bloquea `.env` reales, llaves, certificados, bases `.db`, archivos de más de 5 MB, secretos, rutas
  locales y menciones a herramientas de generación o coautoría en lo preparado para el commit (mismas reglas que
  la verificación de la entrega). `commit-msg` exige castellano, título de 10 a 100 caracteres y ninguna línea de
  coautoría, y recomienda el tipo y el `#issue`. `pre-push` revisa autores y mensajes de los commits nuevos y
  ejecuta `node scripts/verificar-todo.js`; si falla, no sube nada.
- **Emergencias**: `SALTAR_VERIFICACION=1 git push …` omite solo la ejecución de `verificar-todo.js` (la revisión
  de autores y mensajes se hace siempre). Solo con el visto bueno de Diego o Juan, y anotado en el Merge Request.
  No se usa `--no-verify`.
- **Integración continua**: `.gitlab-ci.yml` ejecuta `node scripts/verificar-todo.js` con la imagen oficial de
  Node.js 22 (sin otras dependencias) en cada Merge Request hacia `avance` o `terminado` y en cada push a las
  ramas del equipo. En GitHub hace lo mismo `.github/workflows/pruebas.yml`.
- **Si el GitLab del evento no tiene runners**, el pipeline queda pendiente y no bloquea: la verificación vale la
  del gancho `pre-push`, y quien abre el Merge Request pega su resumen («TODO VERDE …») en la sección
  *Evidencia de la verificación* de la plantilla.

## 8. Configuración en GitHub (la hacen Diego o Juan)

*Settings › Branches* para `staging` y `main`: *Require a pull request before merging*, *Require approvals* (1),
*Require review from Code Owners*, *Require status checks to pass* y sin *force push*. `.github/CODEOWNERS`
asigna todo el repositorio a Diego Landaeta y Juan Laya.
