# Guion y Protocolo de Prueba de Usabilidad (Issue #54 · F7)

> **Propósito:** Observar a **3 personas ajenas al proyecto** completando el flujo ciudadano de extremo a extremo, medir tiempos y dificultades reales y documentar las mejoras aplicadas.

---

## 1. Escenarios de Prueba (4 tareas cronometradas)

| # | Tarea | Punto de partida | Criterio de éxito |
| :---: | :--- | :--- | :--- |
| **T1** | **Enrolar factor TOTP** | Portal de Trámites (`/`) + App Autenticadora (`/app/`) | El participante inicia sesión, configura PIN en la PWA, vincula la cuenta (QR/enlace/manual) y guarda sus 10 códigos de recuperación. |
| **T2** | **Iniciar sesión con segundo factor** | Pantalla de acceso del Portal | El participante cierra sesión, vuelve a entrar con usuario/clave y valida el código TOTP vigente. |
| **T3** | **Trámite sensible con confirmación (*step-up*)** | Panel del ciudadano | El participante solicita un trámite sensible e introduce un nuevo código TOTP para autorizarlo. |
| **T4** | **Recuperar acceso tras pérdida simulada** | Pantalla de segundo factor | El participante usa uno de los 10 códigos de recuperación para recuperar acceso y re-enrolar. |

---

## 2. Plantilla de Registro de Observación (3 participantes)

| Participante | Perfil (sin datos personales) | T1 (seg) | T2 (seg) | T3 (seg) | T4 (seg) | Dificultades observadas | Mejora aplicada |
| :---: | :--- | :---: | :---: | :---: | :---: | :--- | :--- |
| P1 | *Completar en sesión presencial* | — | — | — | — | — | — |
| P2 | *Completar en sesión presencial* | — | — | — | — | — | — |
| P3 | *Completar en sesión presencial* | — | — | — | — | — | — |
