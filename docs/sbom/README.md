# Inventario de software (SBOM)

Generado por `node docs/sbom/generar-sbom.js` el 2026-11-27T14:46:55.463Z con Node.js v22.22.1 sobre la copia de trabajo del commit `dbd5947cbf3d`.
No edite estos archivos a mano: vuelva a ejecutar el script tras cualquier cambio.

| Archivo | Contenido |
| --- | --- |
| [`sbom.cdx.json`](sbom.cdx.json) | SBOM en formato CycloneDX 1.5 (JSON): metadatos, componentes y grafo de dependencias. |
| [`hashes-sha256.txt`](hashes-sha256.txt) | SHA-256 de cada archivo de los componentes propios. Comprobación: `sha256sum -c docs/sbom/hashes-sha256.txt` desde la raíz. |

## Resultado

- **Dependencias npm declaradas: 0** en 4 archivos `package.json` (campos `dependencies`, `devDependencies`, `peerDependencies`, `optionalDependencies`, `bundleDependencies`, `bundledDependencies`).
- **Importaciones de paquetes externos: 0** en 159 archivos JavaScript escaneados.
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
| `backend/` | 0.1.0 | 73 | `fb190c1800217cca…` | `node:assert/strict`, `node:child_process`, `node:crypto`, `node:fs`, `node:fs/promises`, `node:http`, `node:https`, `node:net`, `node:os`, `node:path`, `node:perf_hooks`, `node:sqlite`, `node:test`, `node:url`, `node:util` |
| `authenticator-app/` | 0.0.0+git.dbd5947cbf3d | 19 | `11224c1a07624b12…` | `node:assert/strict`, `node:test` |
| `admin-console/` | 0.0.0+git.dbd5947cbf3d | 38 | `4445bfc1976b681d…` | — (código de navegador) |
| `sdk/` | 1.0.0 | 14 | `1c84524f50ea2683…` | `node:assert/strict`, `node:crypto`, `node:http`, `node:https`, `node:net`, `node:test`, `node:url`, `node:util` |
| `demo-portal-tramites/` | 1.0.0 | 21 | `da05fc3935a36b64…` | `node:assert/strict`, `node:async_hooks`, `node:crypto`, `node:fs`, `node:http`, `node:https`, `node:os`, `node:path`, `node:test`, `node:url` |
| `attack-lab/` | 1.0.0 | 29 | `4cf28cbf950af3c1…` | `node:assert/strict`, `node:child_process`, `node:crypto`, `node:fs`, `node:http`, `node:https`, `node:net`, `node:os`, `node:path`, `node:test`, `node:timers/promises`, `node:tls`, `node:url` |
| `contracts/` | 0.0.0+git.dbd5947cbf3d | 37 | `cfbf45ae248501a1…` | — (sin JavaScript) |
| `deploy/` | 0.0.0+git.dbd5947cbf3d | 14 | `194978b8b3ae2d68…` | `node:child_process`, `node:crypto`, `node:fs`, `node:https`, `node:os`, `node:path`, `node:sqlite`, `node:url` |

El hash de cada componente es el SHA-256 de su lista `"<sha256>  <ruta>\n"` (la de `hashes-sha256.txt`) en orden alfabético.

## Módulos nativos de Node.js

| Módulo | Archivos que lo importan | Uso |
| --- | ---: | --- |
| `node:assert/strict` | 28 | solo pruebas |
| `node:async_hooks` | 1 | ejecución |
| `node:child_process` | 12 | ejecución |
| `node:crypto` | 44 | ejecución |
| `node:fs` | 39 | ejecución |
| `node:fs/promises` | 1 | ejecución |
| `node:http` | 11 | ejecución |
| `node:https` | 9 | ejecución |
| `node:net` | 5 | ejecución |
| `node:os` | 12 | ejecución |
| `node:path` | 34 | ejecución |
| `node:perf_hooks` | 3 | ejecución |
| `node:sqlite` | 4 | ejecución |
| `node:test` | 28 | solo pruebas |
| `node:timers/promises` | 2 | ejecución |
| `node:tls` | 1 | ejecución |
| `node:url` | 21 | ejecución |
| `node:util` | 3 | ejecución |

## Entorno

- Node.js 22.22.1 (mínimo `>=22.5` por `node:sqlite`), con OpenSSL 3.5.5 y SQLite 3.46.1 embebidos.
- `openssl` del sistema: solo para `npm run certs` (certificados de desarrollo).
- Navegador moderno para la app autenticadora y la consola (Web Crypto, Service Worker).
