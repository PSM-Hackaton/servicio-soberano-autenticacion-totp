# Especificación UI/UX — Alineación Estricta con Issue #86 (`DESIGN_SYSTEM.md`)

> **Fuente de verdad prioritaria:** [Issue #86](https://github.com/PSM-Hackaton/servicio-soberano-autenticacion-totp/issues/86) (*Estándar de Diseño y Arquitectura Frontend — `DESIGN_SYSTEM.md`*)  
> **Issues complementarios:** `#39`, `#41`, `#42`, `#43`, `#46`, `#58`, `#67`, `#71`.

---

## Análisis de Brechas (Gap Analysis: Commit `45c7a47` vs. Issue #86)

| Aspecto | Estado en `45c7a47` | Estándar Canónico Issue #86 | Corrección Aplicada |
| :--- | :--- | :--- | :--- |
| **Franja tricolor** | `4 dp` debajo del encabezado | `5 dp` (`33.34%/33.33%/33.33%`) **arriba** del encabezado institucional | Movida arriba del encabezado dentro de `headerContainer` (debajo del `statusBar`/`displayCutout`) con `5 dp` (`@dimen/tricolor_height`) |
| **Modo oscuro** | Solo `values/colors.xml` (claro) | Obligatorio soporte claro + oscuro (`#0C1120`, `#141A2B`, `#2A3349`, `#0B1430`, `#3557C4`, `#6FD0A6`, `#FF8F80`) | Creado `res/values-night/colors.xml` con todos los tokens exactos de Issue #86 |
| **Radios y toque** | Valores fijos (`16 dp`, `12 dp`) | `--radio-s: 8dp`, `--radio-m: 14dp`, `--radio-l: 22dp`, `--toque: 48dp` | Creado `res/values/dimens.xml` y aplicado en tarjetas y botones |
| **Edge-to-Edge (API 35/36)** | `WindowInsetsCompat` en `headerContainer` y `contentScroll` | Respetar `displayCutout` y `systemBars` sin solapamiento | Preservado intacto (`>= 94 px` libre arriba en `1080x2400`) |
| **Seguridad y Persistencia** | `KeystoreVault` + `BiometricPrompt.CryptoObject` + `AccountRepository` | Cero secretos expuestos, errores en español, `FLAG_SECURE` | Preservado intacto |
