# Escalabilidad y crecimiento

Documento principal: [`escalabilidad.pdf`](escalabilidad.pdf) (fuente: [`escalabilidad.html`](escalabilidad.html)).

Explica, con mediciones reales de una instancia, cuántos usuarios e instituciones soporta hoy el servicio,
cuál es su cuello de botella y cómo crecer en seis etapas (afinado, alta disponibilidad, varios nodos con
PostgreSQL autoalojado, federación nacional con HSM y continuidad), siempre con infraestructura propia y
software libre.

Resultado clave (Intel Core i5-12400, NVMe, Node.js 22.22.1): una instancia sostiene ≈ 350 verificaciones
y ≈ 800 validaciones de token por segundo con la configuración actual (≈ 275 000 usuarios con los supuestos
del documento). El límite es la confirmación síncrona a disco de SQLite; con `synchronous=NORMAL` la
capacidad se multiplica por 3 a 5.

## Contenido

| Ruta | Qué es |
| :--- | :--- |
| `escalabilidad.pdf` / `.html` | Documento para el jurado. |
| `medicion/banco.js` | Arranca el servicio real con límites de tasa altos y reloj acelerado (no modifica el producto). |
| `medicion/carga.js` | Generador de carga propio (`node:https`, keep-alive, concurrencia configurable). |
| `medicion/partes.js` | Costo aislado de cada pieza (TOTP, AES, Ed25519, detector, scrypt, SQLite). |
| `medicion/perfil.js` | Resume un perfil de CPU de `node --cpu-prof`. |
| `medicion/medir.sh` | Ejecuta un escenario completo en una carpeta temporal. |
| `datos/` | Resultados crudos de las mediciones publicadas en el documento. |

## Repetir la medición

Requisitos: Node.js 22.5 o superior y los certificados de desarrollo (`cd backend && npm run certs`).
Sin dependencias que instalar. Use una carpeta temporal **fuera del repositorio**: allí se crean el `.env`
de prueba (con secretos aleatorios) y las bases de datos.

```bash
cd docs/escalabilidad/medicion
T=/ruta/temporal/fuera/del/repo
./medir.sh $T full   FULL   1000 8 1,10,50,100   # configuración actual
./medir.sh $T normal NORMAL 1000 8 1,10,50,100   # afinado propuesto (etapa 2)
node partes.js $T                                 # costo por pieza
PERFIL=1 FASES=verify ./medir.sh $T perfil NORMAL 1000 10 10
node perfil.js $T/perfil/CPU*.cpuprofile 25 9
rm -rf $T
```

Cada escenario tarda unos 3 minutos (el enrolamiento de 1 000 usuarios ocupa ≈ 80 s) y deja
`$T/<escenario>/resultados.json`. Variables opcionales: `ACELERACION` (100), `PUERTO` (18900),
`FASES` (`jwks,verify,validate`), `PERFIL=1`.

Para regenerar el PDF desde el HTML:

```bash
chromium --headless --no-sandbox --disable-gpu --no-pdf-header-footer \
  --print-to-pdf=docs/escalabilidad/escalabilidad.pdf file://$PWD/docs/escalabilidad/escalabilidad.html
```
