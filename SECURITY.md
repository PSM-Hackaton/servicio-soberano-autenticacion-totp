# Política de seguridad

## Reportar una vulnerabilidad

No abras un issue público. Escribe directamente a los responsables del repositorio (equipo PSM-Hackaton) con:

- descripción del problema y componente afectado,
- pasos para reproducirlo,
- impacto estimado.

Respondemos lo antes posible y publicamos la corrección cuando esté lista.

## Principios del proyecto

- **Criptografía estándar:** solo algoritmos abiertos y auditados (RFC 6238, HMAC-SHA256/512, AES-256-GCM, Ed25519). Nunca criptografía inventada.
- **Sin secretos en el repositorio:** llaves, contraseñas y tokens se generan en el servidor y nunca se versionan. GitHub bloquea las subidas que contengan secretos.
- **Datos mínimos:** no se guardan nombres, correos ni IP en claro; solo identificadores seudónimos (HMAC).
- **Sin llamadas externas:** el sistema no envía datos ni telemetría a terceros.
- **Dependencias auditadas:** alertas automáticas de vulnerabilidades, `npm audit` antes de cada fusión y SBOM en cada entrega.

## Versiones soportadas

Durante el hackatón solo se mantiene la rama `main`.
