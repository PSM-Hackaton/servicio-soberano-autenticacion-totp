# Ensayo Cronometrado Técnico de la Demostración (Issue #69 · G8)

- **Fecha:** 2026-11-27
- **Entorno:** Linux · Node.js `v22.22.1` · 0 dependencias npm
- **Guion de referencia:** `docs/presentacion/guion-demo.pdf` (ventana objetivo: **5–7 minutos**)

---

## 1. Tiempos reales medidos de comandos de demostración y Plan B

Mediciones obtenidas directamente con `/usr/bin/time` sobre la rama `feat/laya-dia2-rubrica-y-evidencias` (basada en `staging` `4c99f84`):

| Comando | Uso en la demo / Plan B | Resultado | Tiempo real medido |
| :--- | :--- | :---: | :---: |
| `node docs/sbom/generar-sbom.js --comprobar` | Bloque `0:45–1:30` (Soberanía demostrada, 0 deps) | ✅ 0 deps, 159 JS, 0 externas | **0,11 s** |
| `cd backend && npm test` | Plan B si falla arranque en vivo (237 pruebas) | ✅ 237/237 en verde | **9,44 s** |
| `cd demo-portal-tramites && npm test` | Verificación E2E portal → búsqueda por cédula (20 pruebas) | ✅ 20/20 en verde | **4,54 s** |
| `cd attack-lab && npm test` | Plan B laboratorio y proxy de caos sin backend (28 pruebas) | ✅ 28/28 en verde | **2,22 s** |
| `node scripts/verificar-todo.js` | Verificación integral CI (OpenAPI + 340 pruebas + SBOM + higiene) | ✅ TODO VERDE | **18,87 s** |

---

## 2. Presupuesto de tiempo por bloque (Guion 5–7 min)

| Bloque | Ventana | Duración | Responsable sugerido | Margen técnico verificado |
| :--- | :---: | :---: | :--- | :--- |
| 1. El problema | `0:00–0:45` | 45 s | Presentador | Sin ejecución en vivo |
| 2. Soberanía demostrada (`generar-sbom.js` + pestaña Red) | `0:45–1:30` | 45 s | Presentador + Teclado | Comando SBOM tarda **0,11 s** |
| 3. Flujo completo en vivo (Portal → App → JWT → *step-up*) | `1:30–3:00` | 90 s | Teclado (portal/app) | Usuario preparado `V-10.000.002` (reserva `E-80.000.003`) |
| 4. Ataques bloqueados en vivo (`replay`, `jwt`, `spraying`) | `3:00–4:30` | 90 s | Terminal de ataques | Respaldo inmediato en `docs/evidencias/attack-lab-informe-2026-11-26.html` |
| 5. Caos y sin Internet (`escenario-caos.js`) | `4:30–5:20` | 50 s | Terminal de ataques | Reinicio medido 0,33 s; falla cerrado 0 accesos indebidos |
| 6. Consola RBAC y auditoría encadenada | `5:20–6:20` | 60 s | Consola | Sesión iniciada previamente en `/consola/` |
| 7. Impacto, viabilidad y cierre | `6:20–7:00` | 40 s | Presentador / Técnico | Matriz de 27 ítems + escalabilidad + `systemd` |
| **Total planificado** | **`0:00–7:00`** | **7 min** | **Equipo completo** | **Dentro de ventana 5–7 min** |

---

## 3. Grabación del vídeo de respaldo (pendiente presencial con voz)

Para completar el vídeo narrado de respaldo antes de la exposición en vivo, ejecutar en la máquina de la demostración (Linux X11 con `ffmpeg` ya verificado en el entorno):

```bash
ffmpeg -f x11grab -framerate 25 -i :0.0 -t 360 demo-respaldo.mp4
```

- **Estado de ejecución técnica:** `[x]` Comandos de demo, Plan B y suite integral medidos y en verde (**18,87 s** total).
- **Estado de grabación presencial con voz:** `[ ]` Pendiente grabar el archivo `demo-respaldo.mp4` fuera del repositorio (o en almacenamiento local del equipo de exposición) durante el ensayo oral del equipo.
