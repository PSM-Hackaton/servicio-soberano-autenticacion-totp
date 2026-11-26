# Inventario de software (SBOM)

Generado por `node docs/sbom/generar-sbom.js` el 2026-11-26T17:38:18.569Z con Node.js v22.22.1 sobre la copia de trabajo del commit `a992979006e2`.
No edite estos archivos a mano: vuelva a ejecutar el script tras cualquier cambio.

| Archivo | Contenido |
| --- | --- |
| [`sbom.cdx.json`](sbom.cdx.json) | SBOM en formato CycloneDX 1.5 (JSON): metadatos, componentes y grafo de dependencias. |
| [`hashes-sha256.txt`](hashes-sha256.txt) | SHA-256 de cada archivo de los componentes propios. Comprobación: `sha256sum -c docs/sbom/hashes-sha256.txt` desde la raíz. |

## Resultado

- **Dependencias npm declaradas: 0** en 4 archivos `package.json` (campos `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`, `bundleDependencies`, `bundledDependencies`).
- **Importaciones de paquetes externos: 0** en 129 archivos JavaScript escaneados.
- **Módulos nativos de Node.js usados: 17.** Vienen con el entorno de ejecución; no se descarga nada de Internet.
- **Recursos externos en los frontends (CDN, fuentes, scripts remotos): 0.**
- No hay `package-lock.json` porque no hay nada que instalar: `npm install` no es necesario.

## package.json revisados

| Archivo | Nombre | Versión | Node (engines) | Licencia declarada | Dependencias |
| --- | --- | --- | --- | --- | --- |
| `attack-lab/package.json` | `servicio-soberano-totp-attack-lab` | 1.0.0 | >=22.5 | — | 0 |
| `backend/package.json` | `servicio-soberano-autenticacion-totp-backend` | 0.1.0 | >=22.5 | — | 0 |
| `demo-portal-tramites/package.json` | `demo-portal-tramites` | 1.0.0 | >=22 | — | 0 |
| `sdk/package.json` | `@soberano/sdk-totp` | 1.0.0 | >=22 | UNLICENSED | 0 |

## Componentes propios

| Componente | Versión | Archivos | SHA-256 (resumen) | Módulos nativos |
| --- | --- | ---: | --- | --- |
| `backend/` | 0.1.0 | 59 | `fa183d6b76bead00…` | `node:assert/strict`, `node:child_process`, `node:crypto`, `node:fs`, `node:fs/promises`, `node:http`, `node:https`, `node:net`, `node:os`, `node:path`, `node:perf_hooks`, `node:sqlite`, `node:test`, `node:url`, `node:util` |
| `authenticator-app/` | 0.0.0+git.a992979006e2 | 18 | `1b7ef50c2d84eeed…` | `node:assert/strict`, `node:test` |
| `admin-console/` | 0.0.0+git.a992979006e2 | 35 | `50555724edd13817…` | — (código de navegador) |
| `sdk/` | 1.0.0 | 11 | `20a9bcedbfe7e1c7…` | `node:assert/strict`, `node:crypto`, `node:http`, `node:https`, `node:net`, `node:test`, `node:url`, `node:util` |
| `demo-portal-tramites/` | 1.0.0 | 17 | `721eb6704b617034…` | `node:assert/strict`, `node:async_hooks`, `node:crypto`, `node:fs`, `node:http`, `node:https`, `node:os`, `node:path`, `node:test`, `node:url` |
| `attack-lab/` | 1.0.0 | 25 | `4ea552522fa59d98…` | `node:assert/strict`, `node:child_process`, `node:crypto`, `node:fs`, `node:http`, `node:https`, `node:net`, `node:path`, `node:test`, `node:url` |
| `contracts/` | 0.0.0+git.a992979006e2 | 33 | `8e377f9a68b7bc1f…` | — (sin JavaScript) |
| `deploy/` | 0.0.0+git.a992979006e2 | 2 | `430011f0e360c8ed…` | — (sin JavaScript) |

El hash de cada componente es el SHA-256 de su lista `"<sha256>  <ruta>\n"` (la de `hashes-sha256.txt`) en orden alfabético.

## Módulos nativos de Node.js

| Módulo | Archivos que lo importan | Uso |
| --- | ---: | --- |
| `node:assert/strict` | 19 | solo pruebas |
| `node:async_hooks` | 1 | ejecución |
| `node:child_process` | 4 | ejecución |
| `node:crypto` | 32 | ejecución |
| `node:fs` | 25 | ejecución |
| `node:fs/promises` | 1 | ejecución |
| `node:http` | 8 | ejecución |
| `node:https` | 5 | ejecución |
| `node:net` | 4 | ejecución |
| `node:os` | 5 | solo pruebas |
| `node:path` | 24 | ejecución |
| `node:perf_hooks` | 3 | ejecución |
| `node:sqlite` | 2 | ejecución |
| `node:test` | 19 | solo pruebas |
| `node:timers/promises` | 1 | ejecución |
| `node:url` | 14 | ejecución |
| `node:util` | 3 | ejecución |

## Entorno

- Node.js 22.22.1 (mínimo `>=22.5` por `node:sqlite`), con OpenSSL 3.5.5 y SQLite 3.46.1 embebidos.
- `openssl` del sistema: solo para `npm run certs` (certificados de desarrollo).
- Navegador moderno para la app autenticadora y la consola (Web Crypto, Service Worker).
