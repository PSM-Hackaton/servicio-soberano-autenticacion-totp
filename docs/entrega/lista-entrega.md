# Lista de comprobación de la entrega

Servicio Soberano de Autenticación Multifactorial basado en Tiempo (TOTP) · Reto Grupal 1 ·
Hackatón Venezuela INNOVA 2026 · Equipo PSM-Hackaton · revisada el 26-11-2026.

Fuentes: *Instructivo de uso de GitLab — Hackathon 2026* (acceso, ramas `avance` y `terminado`, README de seis
apartados) y *Términos de Referencia y Especificación Técnica v1.0.1* del reto (alcance, requisitos por
componente, estándares de ciberseguridad y criterios de evaluación).

Leyenda: **[x]** hecho, con su evidencia en el repositorio · **[ ]** pendiente (se indica quién lo hace).

---

## 1. Instructivo de GitLab

### 1.1 Acceso y cuentas

- [ ] Cada integrante entra en GitLab con su correo de registro y la contraseña temporal, y la cambia por una
  robusta (12 caracteres o más, con mayúsculas, minúsculas, números y símbolos). **Equipo.**
- [ ] Cada integrante confirma que ve el proyecto asignado al equipo en su panel. **Equipo.**
- [ ] Anotar la **URL del proyecto en GitLab** (botón *Clone*): hace falta para el remoto de la entrega y para
  sustituir `<URL_DEL_PROYECTO>` si el jurado la pide en el Paso 1 del README. **Equipo.**

### 1.2 Carga progresiva y ramas

- [x] Trabajo diario en ramas por integrante (`diego`, `laya`) con commits frecuentes; historial completo en el
  repositorio de trabajo del equipo.
- [x] Herramientas para llevar a GitLab una copia limpia y verificada: subida por etapas el día 1, sincronización
  commit a commit después y comprobación final (herramientas internas del equipo, que no forman parte de la entrega).
- [ ] Merge Request diario de la rama de trabajo hacia **`avance`** (fin de cada jornada). **Equipo, en GitLab.**
- [ ] Merge Request final de `avance` hacia **`terminado`** tras el *code freeze* y la aprobación del líder
  técnico. **Equipo, en GitLab.**
- [ ] Aprobación del Pull Request de integración (`diego`/`laya` → `staging` → `main`) en el repositorio de
  trabajo antes de la última sincronización. **Líder técnico.**
- [ ] Orden explícita del líder técnico para el push final a GitLab. **Líder técnico.**

### 1.3 README.md en la raíz con los seis apartados, en orden

| Apartado | Dónde | Estado |
| --- | --- | --- |
| 1. Nombre del proyecto | `README.md` §1 (título oficial, repositorio y licencia AGPL-3.0) | [x] |
| 2. Participantes | `README.md` §2 (nombre completo y rol de los cinco integrantes) | [x] |
| 3. Descripción del proyecto | `README.md` §3 (problema, propósito, funcionamiento con diagrama, módulos, estructura y documentación) | [x] |
| 4. Alcance | `README.md` §4 (funcionalidades cubiertas y límites de la entrega) | [x] |
| 5. Requerimientos del sistema | `README.md` §5 (Node.js 22.5+, SQLite nativa, 0 dependencias npm, servicios y variables de entorno) | [x] |
| 6. Instalación y despliegue | `README.md` §6 (instalador `deploy/instalar.sh` y Pasos 1–11: clonar, sin `npm install`, `.env`, certificados, semilla, ejecución, pruebas, laboratorio, SBOM y producción) | [x] |

La comprobación automática de la entrega verifica estos seis encabezados y su orden.

---

## 2. Términos de Referencia del reto

### 2.1 Alcance general (plataforma modular, auditable y de código abierto)

- [x] Motor criptográfico TOTP y backend: `backend/src/core/totp/`, `backend/src/core/vault/`, `backend/src/api/`.
- [x] APIs de integración institucional: `contracts/openapi.yaml` (las **31 rutas** del servidor), `sdk/`,
  `docs/api/README.md` y `docs/api/guia-integracion.pdf`.
- [x] Cliente y flujo de enrolamiento: PWA `authenticator-app/` (QR, enlace, URI, clave manual y cámara con
  `camera=(self)` solo en `/app/`), Portal de Trámites con ingreso por cédula; compatibilidad con clientes
  estándar (`docs/evidencias/compatibilidad-clientes-totp.md`).
- [x] Seguridad, resiliencia y heurística local: `backend/src/security/`, `backend/src/heuristics/`, `attack-lab/`.
- [x] Almacenamiento cifrado y consola: AES-256-GCM, TLS 1.3, HMAC para usuarios e IP; `admin-console/` con
  apps, políticas, enrolamientos (suspender, reactivar, revocar, búsqueda por cédula), cuentas, llaves y auditoría.
- [x] Código abierto: `LICENSE` (GNU AGPL-3.0 o posterior).

### 2.2 Requisitos por componente y estándares de ciberseguridad

Cada requisito, citado textualmente, con código y prueba: `docs/cumplimiento/matriz-cumplimiento.pdf`
(**32 de 32 requisitos de los Términos y del enunciado: CUMPLE**).

- [x] CSPRNG, RFC 6238 con HMAC-SHA256/512, ventanas y deriva, JWT Ed25519.
- [x] Almacenamiento local, anti replay, límites de tasa, bloqueo progresivo, anti-DDoS de aplicación.
- [x] Cifrado en reposo y tránsito, anonimización, OWASP (escaneo dinámico propio 12/12), trazabilidad.
- [x] Inventario de dependencias sin componentes comprometidos: `docs/sbom/` (CycloneDX 1.5, **0 dependencias**,
  hashes SHA-256 de cada archivo; `node docs/sbom/generar-sbom.js --comprobar`).

### 2.3 Criterios de evaluación (evidencia preparada)

| Criterio (peso) | Evidencia | Estado |
| --- | --- | --- |
| 1. Buenas prácticas, limpieza y seguridad (15 %) | 309 pruebas en verde; `node scripts/verificar-todo.js` (OpenAPI estricto, 5 suites, SBOM, higiene); CI en `.gitlab-ci.yml`; cobertura en `docs/evidencias/cobertura-2026-11-26.txt` | [x] |
| 2. Ejecución técnica y funcionalidad (25 %) | Flujo completo en vivo; instalación probada (README §6); `docs/evidencias/prueba-despliegue-systemd.md` (10/10) | [x] |
| 3. Uso e integración de IA (10 %) | Detector local Isolation Forest + reglas explicables (`backend/src/heuristics/`); spraying bloqueado en el laboratorio | [x] |
| 4. Impacto y viabilidad (15 %) | `docs/escalabilidad/`, `deploy/`, SDK y guía para el Reto 3 | [x] parcial: falta el modo sistema en un servidor real |
| 5. Innovación y creatividad (10 %) | Todo propio: TLS, QR con Reed-Solomon, JWT, Isolation Forest, proxy de caos | [x] |
| 6. Diseño y experiencia de usuario (15 %) | PWA, portal, consola, `sitio-publico/`, `docs/evidencias/accesibilidad.md`, `docs/manual/manual-usuario.pdf` | [x] parcial: falta la sesión de usabilidad |
| 7. Presentación (10 %) | `docs/presentacion/presentacion.pdf` y `docs/presentacion/guion-demo.pdf` (5–7 min con plan B) | [x] |

---

## 3. Cifras vigentes (26-11-2026)

| Medida | Resultado | Evidencia |
| --- | --- | --- |
| Pruebas automatizadas | **309**, 0 fallos: backend 211, app 26, SDK 28, portal 16, laboratorio 28 | `node scripts/verificar-todo.js` |
| Rutas del servidor en el contrato | **31 de 31** (7 de integración v1, 5 de sistema, 19 de la consola) | `contracts/openapi.yaml` |
| Laboratorio de ataques y caos | **11/11** escenarios, **116/116** verificaciones, 0 hallazgos | `docs/evidencias/attack-lab-informe-2026-11-26.pdf` |
| Escaneo dinámico (DAST propio) | **12/12** verificaciones, 34 sondas, 0 hallazgos | `docs/evidencias/dast-informe-2026-11-26.html` |
| Verificación del despliegue `systemd` | **10/10** controles | `docs/evidencias/prueba-despliegue-systemd.md` |
| Dependencias npm | **0** | `docs/sbom/` |

---

## 4. Comprobaciones de la copia limpia

La comprobación final de la copia limpia (herramienta interna del equipo, sin excepciones aceptadas) terminó sin errores el 26-11-2026:

- [x] Sin material interno de coordinación ni herramientas de preparación de la entrega.
- [x] Sin secretos (`.env`, llaves, certificados, bases de datos) ni rutas locales de las máquinas del equipo.
- [x] Sin marcas de herramientas de terceros ni líneas de coautoría en commits o archivos.
- [x] README con los seis apartados en orden.
- [x] Todas las pruebas en verde dentro de la copia limpia.

---

## 5. Pendiente del lado del equipo

1. **URL del proyecto en GitLab** y remoto `gitlab` configurado en la copia de entrega.
2. **Cuentas de GitLab** de los cinco integrantes activas, con la contraseña temporal cambiada.
3. **Aprobación del Pull Request** de integración en el repositorio de trabajo y orden del líder técnico para el
   push final.
4. **Merge Requests** en GitLab: el diario hacia `avance` y el final de `avance` hacia `terminado`.
5. **Ensayo de la demostración** con el guion (`docs/presentacion/guion-demo.pdf`) y, si hay tiempo, con el
   equipo del Reto 3.

Hoja de ruta declarada (no bloquea la entrega): instalador en modo sistema (root) en un servidor institucional
real, sesión de usabilidad con 3 personas ajenas al equipo, app Android nativa completa sobre `mobile-android/`
y llave maestra en HSM/TPM institucional.
