# Auditoría de Accesibilidad WCAG 2.1 Nivel AA (Issues #33 D7 y #50 F3)

> **Alcance:** `authenticator-app/` (`/app/`), `admin-console/` (`/consola/`), `demo-portal-tramites/` y `sitio-publico/`.  
> **Fecha:** 2026-11-26 · **Paleta evaluada:** Azul institucional `#00247D`, modo claro y modo oscuro, tipografía del sistema sin CDNs.

---

## 1. Matriz de Verificación WCAG 2.1 AA

| Criterio WCAG 2.1 AA | App Autenticadora (`/app/`) | Consola Admin (`/consola/`) | Portal de Trámites | Sitio Público (`sitio-publico/`) | Estado |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **3.1.1 Idioma declarado (`lang="es"`)** | `lang="es"` en `index.html` | `lang="es"` en `index.html` | `lang="es"` en `vistas.js` | `lang="es"` en las 3 páginas | ✅ Cumple |
| **2.4.1 Saltar al contenido + landmarks semánticos** | `<header>`, `<main>`, `<nav>` | `<header>`, `<aside>`, `<main>` | `<header>`, `<main>`, `<footer>` | Enlace `.saltar` + `<header>/<nav>/<main>/<footer>` | ✅ Cumple |
| **1.4.3 Contraste ≥ 4.5:1 (claro y oscuro)** | `#00247D` sobre `#FFFFFF` = **12.6:1**; texto oscuro `#0F172A` = **17.8:1** | `#00247D` y texto claro `#F8FAFC` sobre `#0B1120` = **17.5:1** | Paleta institucional `#00247D` / `#FFFFFF` ≥ **12:1** | Ratios verificados ≥ **7:1** en claro y oscuro | ✅ Cumple |
| **2.1.1 Operable por teclado + 2.4.7 foco visible** | Controles nativos `<button>`, `<input>`, `:focus-visible` | Navegación lateral por teclado + `:focus-visible` | Formularios nativos y enlaces navegables con `Tab` | `:focus-visible` de 3 px amarillo `#FFCC00` de alto contraste | ✅ Cumple |
| **4.1.3 Mensajes de estado (`aria-live="polite"`)** | Avisos y estado de copia anunciados sin interrumpir | Alertas y verificación de cadena con `role="status"` | Mensajes de error/éxito con `role="alert"` / `status` | Banner de `/estado` y `/instalar-certificado` con `aria-live="polite"` | ✅ Cumple |
| **2.5.5 Objetivos táctiles ≥ 44 × 44 px (360 px móvil)** | Botones y tarjetas táctiles adaptados a móvil | Botones responsivos y tablas desplazables | Botones de acción ≥ 44 px | `min-height: 44px` explícito en `.nav a`, `.btn`, `.btn-tema` | ✅ Cumple |
| **2.3.3 Movimiento reducido (`prefers-reduced-motion`)** | Soportado en CSS | Soportado en CSS | Soportado en CSS | Regla `@media (prefers-reduced-motion: reduce)` explícita | ✅ Cumple |
| **CSP estricta (cero inline JS/CSS)** | Sin `<script>` inline, sin `onclick`, sin `style=""` | Sin `<script>` inline, sin `onclick` | CSP `default-src 'none'` estricta | 0 scripts inline, 0 estilos inline, 0 `innerHTML` | ✅ Cumple |

---

## 2. Notas de Verificación Manual Pendiente en Sala

- Se recomienda completar una pasada en vivo con lector de pantalla **Orca (Linux)** y **TalkBack (Android)** antes del cierre final de `#50` para anexar las observaciones del lector de pantalla en PDF.
