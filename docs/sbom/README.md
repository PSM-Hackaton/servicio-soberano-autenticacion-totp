# Inventario de software (SBOM)

Generado por `node docs/sbom/generar-sbom.js` el 2026-11-26T19:55:05.496Z con Node.js v22.22.1 sobre la copia de trabajo del commit `bd923082187e`.
No edite estos archivos a mano: vuelva a ejecutar el script tras cualquier cambio.

| Archivo | Contenido |
| --- | --- |
| [`sbom.cdx.json`](sbom.cdx.json) | SBOM en formato CycloneDX 1.5 (JSON): metadatos, componentes y grafo de dependencias. |
| [`hashes-sha256.txt`](hashes-sha256.txt) | SHA-256 de cada archivo de los componentes propios. Comprobación: `sha256sum -c docs/sbom/hashes-sha256.txt` desde la raíz. |

## Resultado

- **Dependencias npm declaradas: 0** en 4 archivos `package.json` (campos `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`, `bundleDependencies`, `bundledDependencies`).
- **Importaciones de paquetes externos: 0** en 152 archivos JavaScript escaneados.
- **Módulos nativos de Node.js usados: 18.** Vienen con el entorno de ejecución; no se descarga nada de Internet.
- **Recursos externos en los frontends (CDN, fuentes, scripts remotos): 0.**
- No hay `package-lock.json` porque no hay nada que instalar: `npm install` no es necesario.

## package.json revisados

| Archivo | Nombre | Versión | Node (engines) | Licencia declarada | Dependencias |
| --- | --- | --- | --- | --- | --- |
| `attack-lab/package.json` | `servicio-soberano-totp-attack-lab` | 1.0.0 | >=22.5 | — | 0 |
| `backend/package.json` | `servicio-soberano-autenticacion-totp-backend` | 0.1.0 | >=22.5 | — | 0 |
| `demo-portal-tramites/package.json` | `demo-portal-tramites` | 1.0.0 | >=22 | — | 0 |
| `sdk/package.json` | `@soberano/sdk-totp` | 1.0.0 | >=22 | AGPL-3.0-or-later | 0 |

## Componentes propios

| Componente | Versión | Archivos | SHA-256 (resumen) | Módulos nativos |
| --- | --- | ---: | --- | --- |
| `backend/` | 0.1.0 | 66 | `e44a9e2a269b18ac…` | `node:assert/strict`, `node:child_process`, `node:crypto`, `node:fs`, `node:fs/promises`, `node:http`, `node:https`, `node:net`, `node:os`, `node:path`, `node:perf_hooks`, `node:sqlite`, `node:test`, `node:url`, `node:util` |
| `authenticator-app/` | 0.0.0+git.bd923082187e | 19 | `1d42ea34debae19a…` | `node:assert/strict`, `node:test` |
| `admin-console/` | 0.0.0+git.bd923082187e | 38 | `6b92775e69636fbc…` | — (código de navegador) |
| `sdk/` | 1.0.0 | 14 | `21f738b6868b6b10…` | `node:assert/strict`, `node:crypto`, `node:http`, `node:https`, `node:net`, `node:test`, `node:url`, `node:util` |
| `demo-portal-tramites/` | 1.0.0 | 20 | `c7d91a18598fe900…` | `node:assert/strict`, `node:async_hooks`, `node:crypto`, `node:fs`, `node:http`, `node:https`, `node:os`, `node:path`, `node:test`, `node:url` |
| `attack-lab/` | 1.0.0 | 29 | `0aef535da5d32b81…` | `node:assert/strict`, `node:child_process`, `node:crypto`, `node:fs`, `node:http`, `node:https`, `node:net`, `node:os`, `node:path`, `node:test`, `node:tls`, `node:url` |
| `contracts/` | 0.0.0+git.bd923082187e | 34 | `89291c8bcfb84200…` | — (sin JavaScript) |
| `deploy/` | 0.0.0+git.bd923082187e | 14 | `584cd14bfd031aa3…` | `node:child_process`, `node:crypto`, `node:fs`, `node:https`, `node:os`, `node:path`, `node:sqlite`, `node:url` |

El hash de cada componente es el SHA-256 de su lista `"<sha256>  <ruta>\n"` (la de `hashes-sha256.txt`) en orden alfabético.

## Módulos nativos de Node.js

| Módulo | Archivos que lo importan | Uso |
| --- | ---: | --- |
| `node:assert/strict` | 24 | solo pruebas |
| `node:async_hooks` | 1 | ejecución |
| `node:child_process` | 9 | ejecución |
| `node:crypto` | 39 | ejecución |
| `node:fs` | 35 | ejecución |
| `node:fs/promises` | 1 | ejecución |
| `node:http` | 10 | ejecución |
| `node:https` | 9 | ejecución |
| `node:net` | 5 | ejecución |
| `node:os` | 9 | ejecución |
| `node:path` | 31 | ejecución |
| `node:perf_hooks` | 3 | ejecución |
| `node:sqlite` | 4 | ejecución |
| `node:test` | 24 | solo pruebas |
| `node:timers/promises` | 1 | ejecución |
| `node:tls` | 1 | ejecución |
| `node:url` | 18 | ejecución |
| `node:util` | 3 | ejecución |

## Entorno

- Node.js 22.22.1 (mínimo `>=22.5` por `node:sqlite`), con OpenSSL 3.5.5 y SQLite 3.46.1 embebidos.
- `openssl` del sistema: solo para `npm run certs` (certificados de desarrollo).
- Navegador moderno para la app autenticadora y la consola (Web Crypto, Service Worker).
