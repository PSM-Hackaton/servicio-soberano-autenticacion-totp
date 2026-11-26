## Qué entra en este Merge Request

<!-- Origen → destino (p. ej. javier → avance, o avance → terminado) y resumen en 2 o 3 líneas. -->

- **Tipo:** <!-- MR diario a avance | MR final a terminado (tras el code freeze) -->
- **Issues:** <!-- #N, #M (cada cambio responde a un issue) -->
- **Aprobado en GitHub por Diego/Juan:** <!-- enlace al Pull Request aprobado en GitHub (uno por cada trabajo incluido) -->

## Lista de comprobación de quien abre el MR

- [ ] Todo lo incluido se aprobó antes en GitHub por Diego Landaeta o Juan Laya (enlaces arriba) y no se añadió nada después de esa aprobación.
- [ ] `README.md` en la raíz con los títulos exactos de la plantilla del evento, sin numerar y en orden: `# <título>` · `## Participantes` · `## Descripción del proyecto` · `## Alcance` · `## Requerimientos del sistema` · `## Paso a paso de instalación / despliegue`.
- [ ] `node scripts/verificar-todo.js` en verde (pipeline del MR o, si no hay runners, salida del gancho pre-push pegada abajo).
- [ ] Sin secretos: ni `.env` reales, ni llaves, ni certificados (`.pem`, `.key`, `.crt`), ni bases `.db`/`.sqlite`, ni tokens.
- [ ] Sin rastros de herramientas: ni líneas de coautoría en los commits ni menciones a herramientas de generación de contenido.
- [ ] Sin rutas locales de la máquina de nadie (carpetas personales).
- [ ] Autoría real: cada commit es de quien hizo el trabajo, con su nombre completo, a la hora real; mensajes en castellano con referencia al issue; ningún push forzado.
- [ ] Commits pequeños y frecuentes en la rama personal durante la jornada (no un único commit gigante).
- [ ] Si cambia la interfaz (PWA, consola, portal, sitio): capturas o evidencia adjuntas en este MR o en `docs/evidencias/`.
- [ ] Ningún archivo de más de 5 MB.
- [ ] MR final: el code freeze (4 horas antes de la entrega) se respetó; después solo correcciones críticas, `README.md` y ensayo de demo.

## Evidencia de la verificación

```text
(Pegue aquí el resumen final de node scripts/verificar-todo.js: «TODO VERDE …», o el enlace al pipeline.)
```

<!-- Si se usó SALTAR_VERIFICACION=1 en una emergencia, explíquelo aquí y adjunte la verificación posterior. -->

## Revisión del aprobador (solo Diego Landaeta o Juan Laya)

- [ ] Revisé el diff completo y coincide con lo aprobado en GitHub (mismos archivos, sin añadidos).
- [ ] Pipeline en verde, o verificación local revisada y registrada arriba.
- [ ] Merge **sin** *Squash commits* (se conserva el historial de cada integrante).
- [ ] Aprobado y fusionado por: <!-- nombre --> · fecha y hora: <!-- AAAA-MM-DD HH:MM -->
