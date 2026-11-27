# CONTRIBUTING.md — Reglas de Colaboración y Git

## 1. Política Estricta de Remotos
- **GitHub (`origin`):** Remoto **exclusivo** para todo el trabajo del equipo durante el hackatón.
- **GitLab (`gitlab`):** **BLOQUEADO.** Nadie puede hacer `git push` a GitLab hasta que J Laya (Tech Lead) ejecute la orden explícita **`/push gitlab final`**.

## 2. Reglas de Ramas (Cero cambios directos en `main`)
1. **PROHIBIDO** hacer `commit` o `push` directo a `main`.
2. Cada integrante trabaja en su propia rama en GitHub:
   - J Laya (Lead / Arquitectura / Contratos / SDK): **`laya`** (o `feat/lead-*`)
   - Diego Landaeta (Backend / Criptografía): **`diego`** (o `feat/backend-*`)
   - Otros módulos: `feat/<rol>-<modulo>`
3. Integración: abrir Pull Request en GitHub hacia **`staging`** (y de `staging` a `main` solo tras validación conjunta).
4. Antes de subir cambios a GitHub:
   ```bash
   git fetch origin
   git status
   git branch
   ```
5. Toda integración hacia `staging` pasa por Pull Request en GitHub y revisión contra:
   - Respeto de propiedad de carpetas (`ARCHITECTURE.md`).
   - Cumplimiento exacto de `contracts/openapi.yaml` y `contracts/schema.sql`.
   - Cero secretos, `.env`, llaves `.pem`/`.key` ni bases `.db`.
   - Evidencia real de tests y build en verde.

## 3. Higiene de Seguridad
- Jamás subas llaves privadas, certificados generados, bases de datos SQLite ni archivos `.env`.
- Usa `.env.example` para documentar cualquier nueva variable de entorno.

## 4. Code Freeze
- **Code Freeze obligatorio:** 4 horas antes de la entrega final. Después del freeze solo se permiten correcciones críticas de bloqueo, actualización de `README.md` (6 apartados) y ensayos de demo.
