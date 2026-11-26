# Informe de Attack Lab y Pruebas de Caos (Demo)

- **Fecha UTC:** `2026-11-26T17:23:52.730Z`
- **Objetivo:** `harness-local-rfc6238`
- **Escenarios superados:** **7/7**
- **Accesos indebidos concedidos:** **0** (política *fail-closed* estricta)

| Escenario | Categoría | Resultado | Latencia p95 / Recup. | Evidencia |
| :--- | :--- | :--- | :--- | :--- |
| Ataque de Replay (código repetido) | Seguridad | **MITIGADO** | 7.62 ms | 1er intento HTTP 200; replay inmediato HTTP 401 |
| Fuerza bruta distribuida (8 IPs -> 1 cuenta) | Seguridad + IA Local | **MITIGADO** | 2.02 ms | Bloqueo adaptativo 429 activado en intento #5 (estados: 401,401,401,401,429,429,429,429) |
| TOTP Spraying (1 IP -> 10 cuentas) | Seguridad + IA Local | **MITIGADO** | 0.82 ms | Bloqueo por patrón spraying (HTTP 429) activado en la cuenta #6 |
| Deriva de reloj (+5 pasos / +150 s) y Resync | Criptografía RFC 6238 | **VERIFICADO** | 0.98 ms | Fuera de ventana HTTP 401 -> Resync 2 códigos=true -> Verificación post-resync=true |
| Caos: Caída de SQLite (fail-closed + recuperación) | Resiliencia / Caos | **VERIFICADO** | 1.09 ms | /health/ready caída=503, verify caída=503 (0 accesos), recuperación en 1.09 ms |
| Caos: Corte de red + Reintento Idempotente + JWKS Offline | Resiliencia / Caos | **VERIFICADO** | 1.94 ms | Reintento idempotente exitoso (1.94 ms) y JWT validado offline con caché JWKS (kid=iqV5i6_WoN51tvm8C3TBPA) |
| Caos: Latencia artificial (180 ms vs timeout 90 ms) | Resiliencia / Caos | **VERIFICADO** | 101.2 ms | SDK abortó en 101.2 ms con error TIMEOUT (503 fail-closed, 0 accesos indebidos) |
