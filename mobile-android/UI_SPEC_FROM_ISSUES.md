# Especificación UI/UX desde GitHub Issues y PWA Soberana

> **Fuentes consultadas:**
> - **GitHub Issues (`PSM-Hackaton/servicio-soberano-autenticacion-totp`):**
>   - `#39` (M0 · App móvil: decisión de plataforma y arquitectura)
>   - `#41` (M2 · Motor TOTP nativo y almacenamiento seguro en Android Keystore)
>   - `#42` (M3 · Desbloqueo con PIN o biometría y protección `FLAG_SECURE`)
>   - `#43` (M4 · Validación estricta `otpauth://totp/`)
>   - `#46` (M7 · Pruebas de punta a punta de la app móvil)
>   - `#58` (L1 · Paquete `ve.psmhackaton.totpsoberano`, compilación y rama al día)
>   - `#67` (G6 · Evidencia en teléfono real)
>   - `#71` (G10 · Proyecto Gradle compilable y `MainActivity` funcional)
> - **PWA Soberana (`authenticator-app/css/app.css`):** Paleta institucional, contraste WCAG AA y terminología en español.

---

## Tokens Visuales Aplicados (Paridad con `authenticator-app/css/app.css`)

| Token PWA | Color Hex | Uso en Android Material 3 |
| :--- | :---: | :--- |
| `--azul-bandera` / `--barra` | `#00247D` | Encabezado institucional y color primario |
| `--amarillo-bandera` | `#FFCC00` | Franja tricolor superior (tercio izquierdo) |
| `--rojo-bandera` | `#CF142B` | Franja tricolor superior (tercio derecho) |
| `--piedra` | `#EEF1F6` | Fondo general de superficie |
| `--hoja` | `#FFFFFF` | Fondo de tarjetas Material (`MaterialCardView`) |
| `--linea` | `#D5DBE7` | Borde sutil de tarjetas (`1 dp`) |
| `--tinta` / `--tinta-2` | `#141B2D` / `#4A5368` | Tipografía primaria y secundaria |
| `--azul` | `#1A3A8F` | Botones primarios (`MaterialButton`) |
| `--exito` / `--exito-velo` | `#0F6B3E` / `#E6F4EC` | Estado bóveda activa / código copiado |
| `--rojo` / `--rojo-velo` | `#A3261C` / `#F9E6E2` | Errores de validación y acción eliminar |

## Reglas UX y Edge-to-Edge (Android 15/16 · API 35/36)
1. **Respeto estricto de cutout/notch:** `WindowCompat.setDecorFitsSystemWindows(window, false)` + `ViewCompat.setOnApplyWindowInsetsListener` aplicando `WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()` al encabezado y contenedor inferior.
2. **Bóveda bloqueada:** Tarjeta centrada con escudo institucional, estado claro en español y botón principal de `48 dp+` de altura táctil.
3. **Bóveda desbloqueada:** Tarjeta de código TOTP en fuente monoespaciada grande (`36 sp`), barra de progreso de 30 s, acciones Copiar (`EXTRA_IS_SENSITIVE`) y Eliminar con confirmación, más tarjeta de alta con `TextInputLayout` outlined y validación inline (`error`).
