// Catálogo de trámites ficticios. Los "sensibles" exigen de nuevo el código TOTP (step-up).

export const TRAMITES = [
  {
    id: 'certificado',
    titulo: 'Solicitud de certificado',
    resumen: 'Emita un certificado de residencia, antecedentes o estado civil con validez digital.',
    sensible: true,
    icono: 'documento',
    campos: [
      { nombre: 'tipo', etiqueta: 'Tipo de certificado', tipo: 'select', opciones: ['Residencia', 'Antecedentes', 'Estado civil'] },
      { nombre: 'motivo', etiqueta: 'Motivo de la solicitud', tipo: 'text', ayuda: 'Por ejemplo: trámite laboral, beca, alquiler.', max: 80 },
    ],
    exito: (d) => `Certificado de ${d.tipo.toLowerCase()} emitido. Lo recibirá en su bandeja de documentos.`,
  },
  {
    id: 'datos-bancarios',
    titulo: 'Cambio de datos bancarios',
    resumen: 'Actualice la cuenta donde recibe pagos, devoluciones y subsidios.',
    sensible: true,
    icono: 'banco',
    campos: [
      { nombre: 'entidad', etiqueta: 'Entidad bancaria', tipo: 'select', opciones: ['Banco Ejemplo Uno', 'Banco Ejemplo Dos', 'Cooperativa Ejemplo'] },
      { nombre: 'cuenta', etiqueta: 'Número de cuenta (20 dígitos)', tipo: 'text', patron: '[0-9]{20}', patronRe: /^[0-9]{20}$/, ayuda: 'Use una cuenta ficticia, p. ej. 01020304050607080900.', max: 20 },
    ],
    exito: (d) => `Cuenta terminada en ${d.cuenta.slice(-4)} registrada en ${d.entidad}. Los próximos pagos se abonarán allí.`,
  },
  {
    id: 'consulta',
    titulo: 'Consulta de mis trámites',
    resumen: 'Revise el estado de sus solicitudes y comprobantes recientes.',
    sensible: false,
    icono: 'lista',
    campos: [],
  },
  {
    id: 'desactivar-factor',
    titulo: 'Desactivar segundo factor',
    resumen: 'Revoque el autenticador vinculado (por ejemplo, si cambió de teléfono). Deberá enrolarse de nuevo.',
    sensible: true,
    icono: 'llave',
    peligro: true,
    campos: [],
    exito: () => 'Segundo factor revocado en el servicio. En su próximo ingreso deberá vincular un autenticador nuevo.',
  },
];

export const buscarTramite = (id) => TRAMITES.find((t) => t.id === id) ?? null;

/** Valida los campos del formulario del trámite; devuelve { datos } o { error }. */
export function validarCampos(tramite, cuerpo) {
  const datos = {};
  for (const c of tramite.campos) {
    const v = String(cuerpo.get(c.nombre) ?? '').trim();
    if (!v) return { error: `Complete el campo «${c.etiqueta}».` };
    if (c.max && v.length > c.max) return { error: `«${c.etiqueta}» es demasiado largo.` };
    if (c.tipo === 'select' && !c.opciones.includes(v)) return { error: `Seleccione una opción válida en «${c.etiqueta}».` };
    if (c.patronRe && !c.patronRe.test(v)) return { error: `«${c.etiqueta}» no tiene el formato esperado.` };
    datos[c.nombre] = v;
  }
  return { datos };
}
