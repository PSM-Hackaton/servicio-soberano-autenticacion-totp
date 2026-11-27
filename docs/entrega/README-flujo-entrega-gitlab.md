# Guía de Flujo de Entrega y División de Subida a GitLab (Revisión Diego / Juan)

> Documento interno de coordinación (excluido de la entrega pública vía `scripts/exclusiones-entrega.txt`).
> Complementa [`docs/entrega/flujo-gitlab.md`](./flujo-gitlab.md) y [`scripts/README-entrega.md`](../../scripts/README-entrega.md) con el **reparto concreto de subidas para el cierre del Día 2** del Reto 1.

---

## 1. Arquitectura de Repositorios (GitHub vs. GitLab)

| Repositorio | Rol | Qué contiene | Regla de acceso |
| :--- | :--- | :--- | :--- |
| **GitHub (`origin`)** | Trabajo interno del equipo | Historial completo, issues, PRs, coordinación (`TASKS.md`, `SYSTEM_GRAPH.md`, `scripts/entrega-*`) | `staging` y `main` protegidas; requiere aprobación de **Diego o Juan** (`CODEOWNERS`). |
| **GitLab (`gitlab`)** | Entrega oficial del evento | **Copia limpia** filtrada por `scripts/exclusiones-entrega.txt`, autoría real, sin force-push ni notas internas | Ramas personales por integrante; `avance` y `terminado` solo por Merge Request aprobado por Maintainers. |

**Regla de oro:** Nada sube a GitLab sin haber sido aprobado y fusionado previamente en `staging` de GitHub.

---

## 2. División Exacta de Subida al Repo de GitLab

Cada integrante sube **únicamente su propia rama** con **su propia cuenta de GitLab** (autoría real, sin `--force` y sin *Squash commits*):

| Rama en GitLab | Responsable (Cuenta) | Bloques y entregables que le corresponde subir | Quién aprueba/fusiona |
| :--- | :--- | :--- | :--- |
| **`diego`** | Diego Landaeta (`diego-landaeta`) | Núcleo criptográfico TOTP, Vault AES-256-GCM, JWT Ed25519, QR propio, SQLite WAL, seguridad, IA local, servidor HTTPS, attack-lab, M8 dispositivos (`#47`), correcciones de escaneo (`#64`, `#79`) e instalador root (`#68`). | Juan Laya revisa MR (ej. MR `!12` `diego → desarrollo`). |
| **`laya`** | Juan Laya (`lya0509`) | Arquitectura/contratos (`ARCHITECTURE.md`, `contracts/`), DAST propio (`#24`), verificación `systemd` (`#25`), sitio público (`#48`, `#49`, `#52`), centro de ayuda (`#53`), prototipo `mobile-android/` (`#58`, `#71`), QA navegador (`#51`), cifras unificadas (`#66`), desglose de 27 ítems (`#70`), ensayo cronometrado (`#69`) y protocolo móvil (`#67`). | Diego Landaeta revisa PR en GitHub y MR en GitLab. |
| **`javier`** | Javier Rodríguez (`JarviScott`) | Solo si tiene commits aprobados en `staging` del Reto 1 asignados a su autoría. | Diego o Juan. |
| **`enggel`** | Enggel Rodríguez (`metagamingprohd-lang`) | Solo si tiene commits aprobados en `staging` del Reto 1 asignados a su autoría. | Diego o Juan. |
| **`giovani`** | Giovani Marcano (`Giovani2011`) | Solo si tiene commits aprobados en `staging` del Reto 1 asignados a su autoría. | Diego o Juan. |
| **`avance`** | Equipo (protegida) | Integración diaria validada (0 críticos, 0 altos, 0 secretos en pipeline). | **Solo Diego o Juan** (vía MR, sin push directo). |
| **`terminado`** | Equipo (protegida) | Entrega final congelada tras *code freeze* con `README.md` de 6 apartados y 0 hallazgos. | **Solo Diego o Juan** (vía MR desde `avance`). |

---

## 3. Secuencia Exacta de Entrega para el Cierre del Día 2

### Paso 1 — Integración y limpieza en GitHub (`staging`)
1. Revisar y aprobar en GitHub el PR de `feat/laya-dia2-rubrica-y-evidencias` → `staging` (`#70`, `#69`, `#67`, sincronización de docs y SBOM).
2. Cerrar el PR `#81` (`laya → main`), ya absorbido por `#83`.
3. Mantener el PR `#82` (`staging → main`) en pausa hasta completar los últimos puntos del Día 2 (`#68`, evidencias físicas de `#67`/`#69` y revisión conjunta de la presentación).
4. **Importante:** Revisar juntos `docs/presentacion/` antes de subirla a GitLab.

### Paso 2 — Sincronización limpia por autor hacia GitLab
Una vez fusionado en `origin/staging`, cada dueño sincroniza sus commits aprobados desde su copia limpia:

```sh
git fetch origin
# 1) Previsualizar qué commits irían a cada rama (no modifica nada)
sh scripts/sincronizar-gitlab.sh --entrega ../entrega-gitlab --hasta origin/staging --plan

# 2) Sincronizar y subir (el script pide escribir SI antes de cada push)
#    REGLA: cada persona responde SI SOLO al push de su propia rama.
sh scripts/sincronizar-gitlab.sh --entrega ../entrega-gitlab --hasta origin/staging --subir
```

### Paso 3 — Merge Requests en GitLab y verificación de pipeline
1. **Juan** revisa y aprueba el MR `!12` (`diego → desarrollo`) en GitLab.
2. **Diego** revisa y aprueba el MR de `laya` tras la subida del bloque del Día 2.
3. **Diego o Juan** abren y fusionan el MR hacia **`avance`** (sin *Squash commits*) usando `.gitlab/merge_request_templates/Entrega.md`.
4. Confirmar que el pipeline oficial de **`avance`** termina con **0 críticos, 0 altos y 0 secretos**.

### Paso 4 — Code Freeze y paso final a `terminado`
1. Fusionar PR `#82` (`staging → main`) en GitHub con `node scripts/verificar-todo.js` en verde.
2. Validar el árbol limpio final en local:
   ```sh
   sh scripts/preparar-entrega.sh --ref main --final --salida /tmp/final-verificacion
   ```
3. Abrir y fusionar en GitLab el Merge Request final **`avance` → `terminado`** (solo Diego o Juan) y confirmar pipeline en verde.

---

## 4. Controles Obligatorios Antes de Subir

- `node scripts/verificar-todo.js` en **TODO VERDE** (OpenAPI estricto 33 rutas, 340 pruebas, SBOM 0 dependencias e higiene).
- Ganchos instalados en ambos repositorios (`sh scripts/instalar-hooks.sh` y `sh scripts/instalar-hooks.sh --repo ../entrega-gitlab`).
- Prohibido en GitLab: `.env` reales, certificados/llaves, rutas `/home/`, coautorías automáticas, material listado en `scripts/exclusiones-entrega.txt` o menciones internas a escaneos/tablero/simulador.
