# Cómo contribuir

## Ramas

| Rama | Uso | Protección |
|---|---|---|
| `diego` | Trabajo de Diego | Libre |
| `laya` | Trabajo de Laya | Libre |
| `staging` | Integración y pruebas | Solo por pull request aprobado |
| `main` | Versión estable que se entrega | Solo por pull request aprobado |

## Flujo

1. Trabaja en tu rama y sube tus commits.
2. Abre un pull request de tu rama hacia `staging`.
3. La otra persona revisa y aprueba. Todos los comentarios deben quedar resueltos.
4. Cuando `staging` funciona y está probado, se abre un pull request de `staging` hacia `main`.
5. Después de cada fusión, actualiza tu rama desde `staging` (`git pull origin staging`).

En `staging` y `main` no se permite subir directamente, forzar la subida ni borrar la rama. Estas reglas también se aplican a los administradores.

## Reglas

- Commits a nombre de quien hace el cambio, con mensajes claros en castellano.
- Nunca subir llaves, contraseñas, tokens ni archivos `.env`.
- Ejecutar los tests y `npm audit` antes de pedir revisión.
- Entregables y documentación en PDF dentro de `docs/`.
