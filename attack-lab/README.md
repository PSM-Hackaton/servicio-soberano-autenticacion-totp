# attack-lab — ataques simulados y pruebas de caos

Laboratorio para demostrar en vivo, contra **nuestro propio servicio local**, que el servicio TOTP
soberano resiste ataques reales, falla cerrado ante caídas de red y que el **detector local de
anomalías** reacciona a patrones de ataque. Cumple las secciones 5.5 a 5.7 de
`docs/analisis/analisis-tecnico.html`.

- **Cero dependencias**: solo módulos nativos de Node.js 22 (`node:https`, `node:net`, `node:crypto`, `node:test`).
- **Reutiliza el motor propio**: los códigos se generan con `backend/src/core/totp/totp.js` y los JWT se
  validan offline con `backend/src/core/tokens/tokens.js`.
- **Solo localhost**: todos los scripts (y el proxy de caos) se niegan a apuntar a un host que no sea
  `localhost`, `127.x.x.x` o `::1`. Para un entorno **propio** en otra máquina existe la bandera explícita
  `--permitir-host`. **Nunca** se usa contra sistemas de terceros.
- `--inseguro` (no verificar el certificado TLS) solo se acepta contra localhost. Por defecto se usa la CA
  local `backend/certs/ca.crt` si existe (`npm run certs` en `backend/`), o la que indiques con `--ca`.

## Puesta en marcha

```bash
# 1. Backend (en otra terminal)
cd backend && npm run env && npm run certs && npm run seed && npm start
#    La semilla imprime client_id y client_secret de "Portal de Trámites" y "Reto 1" UNA sola vez.

# 2. Credenciales de las apps de prueba (argumentos, variables o archivo)
export ATTACK_CLIENT_ID=app_...            ATTACK_CLIENT_SECRET=...
export ATTACK_CLIENT_ID_2=app_...          ATTACK_CLIENT_SECRET_2=...   # opcional: prueba "otra audiencia"
#    o bien: --credenciales credenciales.json  con { "apps": [ { "client_id": "...", "client_secret": "..." }, ... ] }

# 3. Todo el laboratorio + informe
node attack-lab/ejecutar-todo.js
#    → attack-lab/resultados/informe-<fecha>.json y informe-<fecha>.html (autocontenido, sin recursos externos)

# Pruebas del propio laboratorio (utilidades y proxy contra un servidor eco local)
cd attack-lab && npm test
```

Opciones comunes a todos los scripts:

| Opción | Uso |
| --- | --- |
| `--url https://localhost:8443` | Destino (variable `ATTACK_URL`). |
| `--client-id/--client-secret`, `--client-id-2/--client-secret-2`, `--credenciales archivo.json` | Apps de prueba. |
| `--ca ruta.crt` · `--inseguro` | Confianza TLS (inseguro solo en localhost). |
| `--permitir-host` | Permite un host no local **propio**. |
| `--detallado` · `--json` · `--sin-color` | Traza con hora · resultado en JSON · sin colores ANSI. |
| `--sin-origenes` | No usar direcciones 127.x de origen (ver más abajo). |

`ejecutar-todo.js` añade `--solo replay,jwt`, `--omitir caos`, `--rapido` (no espera la escalada del
bloqueo), `--pausa 3` (segundos entre escenarios), `--salida carpeta` y
`--comando-arranque "node src/main.js" --pid-backend <pid>` para incluir el escenario de reinicio.
El informe sustituye las rutas absolutas por rutas relativas al repositorio (`~` para la carpeta
personal, `<tmp>` para las temporales); `ATTACK_OCULTAR_RUTAS=/ruta/a,/ruta/b` añade otras carpetas a ocultar.

### Orígenes simulados (IP distintas sin salir de la máquina)

El servicio **no confía en `X-Forwarded-For`** (correcto: cualquiera podría falsificarla), así que esa
cabecera no sirve para simular IP. En Linux todo `127.0.0.0/8` es loopback: el laboratorio abre cada
conexión desde una dirección distinta (`127.<ejecución>.<escenario>.<n>`) y el servidor ve **IP de origen
reales y distintas**. Además, cada escenario y cada ejecución usan su propio bloque, para que el historial
que el detector acumula por origen en un ataque no contamine el siguiente. En macOS (sin alias de loopback)
se detecta automáticamente y se cae a una sola IP; los escenarios lo indican en sus notas.

El origen que puntúan el detector y el límite por origen es HMAC(app_id + ':' + IP del usuario final):
la `client_ip` que envía un integrador (un portal reenvía la IP de cada ciudadano) o, si no la envía, la
IP de la conexión. `origen-compartido.js` usa una sola IP de conexión (la «del portal») con muchas
`client_ip` de los rangos de documentación (RFC 5737), nunca direcciones reales.

## Escenarios

Cada archivo es ejecutable (`node attack-lab/escenarios/replay.js …`) e importable
(`import replay from './escenarios/replay.js'` → `{ id, nombre, demuestra, ejecutar(ctx, res) }`).
Cada verificación registra **esperado / obtenido / OK·FALLO**; las observaciones informativas salen como INFO.

| Escenario | Qué hace | Qué demuestra |
| --- | --- | --- |
| `escenarios/replay.js` | Crea un usuario (enrolamiento + activación con la URI `otpauth://` devuelta), verifica un código y lo reenvía; compara la respuesta con la de un código incorrecto; luego manda el mismo código nuevo 10 veces **en paralelo**. | Anti-replay atómico (`last_step < T`): el reenvío da `401 VERIFICATION_FAILED` **idéntico** (estado, cuerpo y cabeceras) a un código incorrecto —sin oráculo—, queda registrado como `replay` en `/metrics` y en la carrera se acepta exactamente uno. |
| `escenarios/deriva.js` | Envía en ráfaga los códigos de T+1 a T+12; resincroniza otro usuario con T+8/T+9 y prueba T+10 y una resincronización a ±11. | La deriva ya no se arrastra: solo entra T+1; solo `resync` fija derivas mayores (hasta ±10) y `verify` respeta ese tope. |
| `escenarios/jwt.js` | Obtiene un JWT legítimo y prueba: payload alterado, firma rota, `alg: none`, confusión HS256, `kid` desconocido, caducado, clave ajena, otra audiencia (app 2 real), reutilización del `jti`. Valida además offline con `/.well-known/jwks.json`. | Todos rechazados; el legítimo vale una sola vez. `--esperar-caducidad` prueba la caducidad real (≈5,5 min). |
| `escenarios/entradas.js` | 37 peticiones malformadas: JSON roto, campos extra, tipos incorrectos, `__proto__`, 5 000 niveles, 2 MiB con y sin `Content-Length`, `Content-Type` incorrecto, rutas raras, métodos no permitidos, credenciales ausentes… | Siempre 4xx con error genérico, sin 5xx ni rastros internos; cabeceras de seguridad presentes; `/health` sano al final. |
| `escenarios/fuerza-bruta.js` | Códigos incorrectos secuenciales contra una cuenta; insiste durante el bloqueo, prueba el código **correcto** bloqueado y, tras vencer el primer escalón, vuelve a fallar. | 429 en el 6.º intento con `Retry-After: 30`; ni el código correcto pasa; al vencer, el siguiente fallo vuelve a bloquear (30 s → 2 min → 10 min → 1 h, o 5 min si el detector se adelanta), siempre con el mismo `TOO_MANY_REQUESTS` genérico. |
| `escenarios/fuerza-bruta-distribuida.js` | 40 IP distintas, un intento cada una, contra la misma cuenta. | Rotar de IP no sirve: el bloqueo es por cuenta; el titular legítimo también queda protegido (falla cerrado). |
| `escenarios/spraying.js` | Un origen prueba 2 códigos en 20 cuentas (6 reales + 14 inexistentes) y luego intenta una verificación legítima desde ese origen. | Ninguna cuenta comprometida; respuestas y tiempos idénticos para cuentas reales e inexistentes (sin enumeración); el **detector de anomalías** bloquea el origen (Δ `anomaly_blocked` en `/metrics`) con un 429 `TOO_MANY_REQUESTS` genérico que no revela puntuación, razones ni umbrales (solo constan en `attempts`, la bitácora y `/admin/api/anomalies`). |
| `escenarios/origen-compartido.js` | Una sola IP de conexión (la «del portal»): 24 ciudadanos con `client_ip` distintas fallan 2 veces cada uno; luego un atacante con una única `client_ip` recorre 20 cuentas. Contraste informativo sin `client_ip`. | Los fallos de muchos ciudadanos no bloquean a un ciudadano legítimo del mismo portal; el atacante sí queda bloqueado (incluso con un código correcto), sin afectar al legítimo ni a la cuenta de la víctima. |
| `escenarios/inundacion.js` | 400 verificaciones con concurrencia 50 desde un origen mientras otro sondea `/health` cada 100 ms (`--peticiones`, `--concurrencia`). | 429 (limitador por origen + detector), 0 errores 5xx, `/health` disponible al 100 % para los demás. |
| `caos/escenario-caos.js` | Ráfaga continua de verificaciones a través del **proxy de caos**: base → latencia 800 ms → corte total 10 s → restauración. El titular legítimo verifica en cada fase como el SDK (3 s de espera, 1 reintento con la misma `Idempotency-Key`). | **Falla cerrado**: 0 códigos incorrectos aprobados; nadie entra durante el corte; con latencia funciona más lento; tiempo de recuperación medido (objetivo < 30 s). |
| `caos/reinicio.js` | Bloquea una cuenta real y un usuario inexistente, mata el backend (`--pid`, `SIGKILL` por defecto), lo relanza con `--comando` y mide hasta `/health/ready` 200. | Recuperación en segundos y los bloqueos sobreviven al reinicio (persisten en la base de datos), también el del usuario inexistente (calculado desde `attempts`: sin enumeración tras reiniciar). |

### Proxy de caos (`caos/proxy-caos.js`)

Proxy TCP propio (`node:net`) que reenvía los bytes TLS sin descifrarlos:

```bash
node attack-lab/caos/proxy-caos.js --escuchar 9443 --destino localhost:8443 [--latencia 800] [--jitter 100] [--perdida 30 --modo-perdida silencio] [--corte]
# y apunta el cliente (portal, SDK, navegador) a https://localhost:9443
```

Teclas en vivo: `l` latencia sí/no · `+`/`-` ±100 ms · `c` corte sí/no · `p` pérdida 0→10→30→50→100 % ·
`m` modo de pérdida (`reset` cierra la conexión, `silencio` la acepta y no la reenvía: el cliente agota su
espera) · `k` matar conexiones activas · `r` restaurar · `s` estadísticas · `q` salir.
La latencia es RTT adicional (mitad por sentido) y conserva el orden de los datos aunque haya jitter.

## Guion de demo (3 minutos)

Preparación (antes de subir al escenario): backend arrancado, credenciales exportadas, una terminal grande
con `--detallado`, y la consola admin abierta en «Anomalías».

1. **0:00 – 0:30 · Replay.** `node attack-lab/escenarios/replay.js --detallado`
   «Robamos un código válido y lo reenviamos: rechazado, y con la misma respuesta que un código cualquiera (el atacante ni siquiera sabe que el código era bueno). Diez envíos a la vez del mismo código: exactamente uno entra.»
2. **0:30 – 1:00 · JWT.** `node attack-lab/escenarios/jwt.js`
   «Alteramos el token, le ponemos `alg: none`, lo firmamos con otra clave, lo usamos en otra app y lo reutilizamos: todo rechazado. El integrador lo valida incluso sin red, con nuestras claves públicas.»
3. **1:00 – 1:45 · Spraying + detector local de anomalías.** `node attack-lab/escenarios/spraying.js`
   «Un atacante prueba pocas veces muchas cuentas para no disparar el bloqueo por cuenta. Al quinto intento el detector local bloquea el origen; al atacante solo le llega un 429 genérico, y las razones las ve el equipo de seguridad en la consola admin; todo se calcula en nuestra máquina, sin servicios externos.» Señalar las razones en la consola admin («Anomalías»).
4. **1:45 – 2:40 · Caos.** `node attack-lab/caos/escenario-caos.js --detallado`
   «Metemos 800 ms de latencia: el usuario entra, más lento. Cortamos la red 10 s: nadie entra, ningún código incorrecto se aprueba (falla cerrado). Restauramos: se recupera en milisegundos.»
5. **2:40 – 3:00 · Informe.** Abrir `attack-lab/resultados/informe-<fecha>.html` de la última ejecución de
   `ejecutar-todo.js` (preparada antes): «11 escenarios, todas las verificaciones con esperado y obtenido.»

Plan B sin backend: `npm test` en `attack-lab/` (26 pruebas, incluido el proxy contra un servidor eco).

## Estructura

```text
attack-lab/
├── ejecutar-todo.js        # orquestador + informe JSON/HTML
├── lib/                    # config y guardia de destino, cliente HTTPS, TOTP, métricas, consola, informe
├── escenarios/             # replay, jwt, entradas, deriva, fuerza-bruta, fuerza-bruta-distribuida, spraying, origen-compartido, inundacion
├── caos/                   # proxy-caos, escenario-caos, reinicio
├── tests/                  # node:test (utilidades y proxy)
└── resultados/             # informes generados (ignorados por git salvo .gitkeep)
```

Los usuarios de prueba usan `user_ref` opacos (`lab-<ejecución>-<n>`), nunca datos personales.
