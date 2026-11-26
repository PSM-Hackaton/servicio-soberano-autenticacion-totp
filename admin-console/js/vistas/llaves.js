// Llaves de firma Ed25519: llave activa, llaves en solo verificación y rotación con
// confirmación de doble paso (explicación + escribir ROTAR).
import { h, reemplazar, tiempo, relativo, idUnico } from '../dom.js';
import { icono } from '../iconos.js';
import { api, mensajeDeError } from '../api.js';
import { cabeceraPagina, tarjeta, estadoError, esqueleto, insigniaEstado, vacio, abrirDialogo, notificar, botonConPermiso, valorHash } from '../ui.js';

const PALABRA = 'ROTAR';

export function montar(raiz, ctx) {
  const puedeRotar = ctx.puede('llaves.rotar');
  const zonaActiva = h('div', null, esqueleto(3));
  const zonaLista = h('div', null, esqueleto(4));
  let datos = null;

  const botonRotar = botonConPermiso({ permitido: puedeRotar, motivo: ctx.motivo('llaves.rotar'), class: 'boton boton--primario' }, icono('rotar'), h('span', { text: 'Rotar llave de firma' }));
  botonRotar.addEventListener('click', () => paso1());

  reemplazar(raiz,
    cabeceraPagina({ titulo: 'Llaves de firma', descripcion: 'Llaves Ed25519 (EdDSA) con las que se firman los tokens de verificación. La rotación no invalida los tokens ya emitidos.', acciones: [botonRotar] }),
    !puedeRotar ? h('p.aviso-rol', null, icono('candado'), `Tu rol (${ctx.sesion.rol}) permite consultar las llaves, no rotarlas.`) : null,
    h('div.rejilla-panel', null,
      tarjeta({ titulo: 'Llave activa', clase: 'col-1 tarjeta--destacada' }, zonaActiva),
      h('div.col-2.columna-pila', null,
        tarjeta({ titulo: 'Historial de llaves', subtitulo: 'Las llaves en solo verificación siguen publicadas en el JWKS', clase: 'tarjeta--tabla' }, zonaLista),
        tarjeta({ titulo: 'Ciclo de vida de una llave' }, cicloVida()))));

  function pintar() {
    const activa = datos.llaves.find((k) => k.kid === datos.activa) ?? datos.llaves.find((k) => k.estado === 'activa');
    reemplazar(zonaActiva, activa
      ? h('div.llave-activa', null,
        h('div.llave-icono', null, icono('llaves')),
        h('p.llave-kid', null, h('code', { text: activa.kid })),
        h('dl.datos-clave', null,
          h('dt', { text: 'Algoritmo' }), h('dd', { text: `${activa.alg} · ${activa.crv}` }),
          h('dt', { text: 'Creada' }), h('dd', null, tiempo(activa.created_at)),
          h('dt', { text: 'Antigüedad' }), h('dd', { text: activa.created_at ? relativo(activa.created_at).replace(/^hace /, '') : '—' }),
          h('dt', { text: 'Publicación' }), h('dd', null, h('a.enlace', { href: '/.well-known/jwks.json', target: '_blank', rel: 'noopener noreferrer', text: '/.well-known/jwks.json' }))),
        h('p.ayuda', null, icono('info'), ' La llave privada se guarda cifrada con AES-256-GCM y nunca sale del servidor.'))
      : vacio('Sin llave activa', 'El servicio no informa de una llave activa.', 'aviso'));

    const lista = datos.llaves;
    reemplazar(zonaLista, lista.length
      ? h('div.tabla-contenedor', null, h('table.tabla.tabla--apilable.tabla--llaves', null,
        h('caption.solo-lectores', { text: 'Historial de llaves de firma' }),
        h('thead', null, h('tr', null, ['Identificador (kid)', 'Estado', 'Algoritmo', 'Creada', 'Rotada'].map((t) => h('th', { scope: 'col', text: t })))),
        h('tbody', null, lista.map((k) => h('tr', { class: k.estado === 'retirada' ? 'fila-apagada' : null },
          h('td', { dataset: { etiqueta: 'kid' } }, valorHash(k.kid, { corto: false, etiqueta: 'kid' })),
          h('td', { dataset: { etiqueta: 'Estado' } }, insigniaEstado(k.estado)),
          h('td', { dataset: { etiqueta: 'Algoritmo' }, text: `${k.alg} · ${k.crv}` }),
          h('td', { dataset: { etiqueta: 'Creada' } }, tiempo(k.created_at)),
          h('td', { dataset: { etiqueta: 'Rotada' } }, tiempo(k.rotated_at)))))))
      : vacio('Sin llaves', 'No hay llaves registradas.'));
  }

  // ---------------------------------------------------------------- rotación en dos pasos
  function paso1() {
    const cancelar = h('button.boton.boton--secundario', { type: 'button', text: 'Cancelar' });
    const continuar = h('button.boton.boton--primario', { type: 'button', text: 'Continuar' });
    const cerrar = abrirDialogo({
      titulo: 'Rotar llave de firma · Paso 1 de 2',
      contenido: [
        h('p', { text: 'Se generará una nueva llave Ed25519 que pasará a firmar todos los tokens nuevos.' }),
        h('ul.lista-consecuencias', null,
          h('li', null, icono('check', { clase: 'icono--ok' }), 'La llave actual ', h('code', { text: datos?.activa ?? '—' }), ' pasa a «solo verificación».'),
          h('li', null, icono('check', { clase: 'icono--ok' }), 'Los tokens ya emitidos siguen siendo válidos hasta su expiración.'),
          h('li', null, icono('check', { clase: 'icono--ok' }), 'Las aplicaciones que validan con el JWKS obtendrán la llave nueva automáticamente.'),
          h('li', null, icono('aviso', { clase: 'icono--aviso' }), 'Las aplicaciones que fijaron el kid manualmente deberán actualizarlo.')),
      ],
      pie: [cancelar, continuar],
    });
    cancelar.addEventListener('click', cerrar);
    continuar.addEventListener('click', () => paso2());
  }

  function paso2() {
    const id = idUnico('rotar');
    const input = h('input', { id, type: 'text', autocomplete: 'off', autocapitalize: 'characters', spellcheck: 'false', 'aria-describedby': `${id}-ayuda`, class: 'input-confirmacion', autofocus: true });
    const atras = h('button.boton.boton--secundario', { type: 'button', text: 'Volver' });
    const rotar = h('button.boton.boton--peligro', { type: 'button', disabled: true }, icono('rotar'), h('span', { text: 'Rotar ahora' }));
    const cerrar = abrirDialogo({
      titulo: 'Rotar llave de firma · Paso 2 de 2',
      tono: 'peligro',
      contenido: [
        h('p', { text: 'Esta operación queda registrada en la bitácora de auditoría con tu usuario.' }),
        h('div.campo', null,
          h('label', { for: id }, 'Escribe ', h('strong.palabra-clave', { text: PALABRA }), ' para confirmar'),
          input,
          h('p.ayuda', { id: `${id}-ayuda`, text: 'Distingue mayúsculas. El botón se habilita al escribir la palabra exacta.' })),
      ],
      pie: [atras, rotar],
    });
    input.addEventListener('input', () => { rotar.disabled = input.value !== PALABRA; });
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !rotar.disabled) rotar.click(); });
    atras.addEventListener('click', () => paso1());
    rotar.addEventListener('click', async () => {
      if (input.value !== PALABRA) return;
      rotar.disabled = true;
      rotar.replaceChildren(h('span.spinner.spinner--claro', { 'aria-hidden': 'true' }), 'Rotando…');
      try {
        const r = await api.rotarLlave();
        cerrar();
        resultado(r);
        await cargar();
      } catch (e) {
        rotar.disabled = false;
        rotar.replaceChildren(icono('rotar'), h('span', { text: 'Rotar ahora' }));
        notificar(mensajeDeError(e), e?.status === 403 ? 'aviso' : 'peligro');
      }
    });
  }

  function resultado(r) {
    const nuevo = r?.new_kid ?? r?.newKid;
    const previo = r?.previous_kid ?? r?.previousKid;
    const listo = h('button.boton.boton--primario', { type: 'button', text: 'Entendido' });
    const cerrar = abrirDialogo({
      titulo: 'Llave rotada',
      contenido: [
        h('div.alerta.alerta--ok', null, icono('ok'), h('p', { text: 'La nueva llave ya firma los tokens emitidos a partir de ahora.' })),
        h('dl.datos-clave', null,
          h('dt', { text: 'Nueva llave' }), h('dd', null, h('code', { text: nuevo ?? '—' })),
          h('dt', { text: 'Llave anterior' }), h('dd', null, previo ? h('code', { text: previo }) : '—', previo ? ' · solo verificación' : ''),
          h('dt', { text: 'Fecha' }), h('dd', null, tiempo(r?.rotated_at ?? r?.rotatedAt))),
      ],
      pie: [listo],
    });
    listo.addEventListener('click', cerrar);
    notificar('Llave de firma rotada correctamente.', 'ok');
  }

  async function cargar() {
    try {
      datos = await api.llaves();
      pintar();
    } catch (e) {
      if (e?.status !== 401) reemplazar(zonaLista, estadoError(mensajeDeError(e), cargar));
    }
  }
  cargar();
  return { refrescar: cargar };
}

function cicloVida() {
  const etapa = (estado, titulo, texto) => h('li.ciclo-etapa', null, h('span', { class: `ciclo-marca ciclo-marca--${estado}`, 'aria-hidden': 'true' }), h('div', null, h('strong', { text: titulo }), h('p', { text: texto })));
  return h('div', null,
    h('ol.ciclo', null,
      etapa('activa', 'Activa', 'Firma todos los tokens nuevos. Solo hay una a la vez.'),
      etapa('verificacion', 'Solo verificación', 'Tras rotar, valida los tokens emitidos antes de la rotación (vida máxima del token: 5 min).'),
      etapa('retirada', 'Retirada', 'Deja de publicarse en el JWKS; los tokens firmados con ella ya no se aceptan.')),
    h('p.ayuda', null, icono('info'), ' Recomendación: rotar periódicamente y de inmediato ante cualquier sospecha de compromiso. Cada rotación queda en la bitácora.'));
}
