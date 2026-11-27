// Mejoras progresivas del portal. Todo funciona sin JavaScript; esto solo añade comodidad.
'use strict';

(function () {
  const formato = (s) => `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;

  // Cuenta atrás del bloqueo (429): al terminar, rehabilita el formulario.
  document.querySelectorAll('[data-cuenta-atras]').forEach((el) => {
    let restante = Number(el.getAttribute('data-cuenta-atras')) || 0;
    const tic = () => {
      restante -= 1;
      if (restante <= 0) {
        clearInterval(id);
        el.textContent = '0:00';
        const aviso = el.closest('.aviso');
        if (aviso) {
          aviso.classList.remove('aviso-bloqueo');
          aviso.classList.add('aviso-info');
          const p = aviso.querySelector('p');
          if (p) p.textContent = 'Ya puede intentarlo de nuevo con el código vigente.';
        }
        document.querySelectorAll('form[data-bloqueado]').forEach((f) => {
          f.removeAttribute('data-bloqueado');
          f.querySelectorAll('input, button').forEach((c) => { c.disabled = false; });
          const campo = f.querySelector('[data-codigo]');
          if (campo) campo.focus();
        });
        return;
      }
      el.textContent = formato(restante);
    };
    const id = setInterval(tic, 1000);
  });

  // Campo de código: solo dígitos.
  document.querySelectorAll('[data-codigo]').forEach((el) => {
    el.addEventListener('input', () => {
      const limpio = el.value.replace(/\D+/g, '').slice(0, 8);
      if (limpio !== el.value) el.value = limpio;
    });
  });

  // Evita el doble envío (un código TOTP repetido sería rechazado como replay).
  document.querySelectorAll('form[data-un-envio]').forEach((f) => {
    f.addEventListener('submit', (ev) => {
      if (f.getAttribute('aria-busy') === 'true') { ev.preventDefault(); return; }
      f.setAttribute('aria-busy', 'true');
      const b = f.querySelector('button[type="submit"]');
      if (b) { b.dataset.texto = b.textContent; b.classList.add('enviando'); b.textContent = 'Verificando…'; }
    });
  });

  // Copiar al portapapeles (clave manual, códigos de recuperación).
  document.querySelectorAll('[data-copiar]').forEach((b) => {
    b.addEventListener('click', async () => {
      const origen = document.querySelector(b.getAttribute('data-copiar'));
      if (!origen) return;
      const items = origen.querySelectorAll('li');
      const texto = items.length ? Array.from(items, (li) => li.textContent.trim()).join('\n') : origen.textContent.replace(/\s+/g, '');
      const original = b.textContent;
      try {
        await navigator.clipboard.writeText(texto);
        b.textContent = 'Copiado';
      } catch {
        const rango = document.createRange();
        rango.selectNodeContents(origen);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(rango);
        b.textContent = 'Seleccionado: pulse Ctrl+C';
      }
      setTimeout(() => { b.textContent = original; }, 2500);
    });
  });

  document.querySelectorAll('[data-imprimir]').forEach((b) => b.addEventListener('click', () => window.print()));

  // Menú principal: en pantallas estrechas se colapsa tras un botón (sin JS queda siempre visible).
  const menu = document.querySelector('[data-menu]');
  const botonMenu = menu && menu.querySelector('[data-menu-boton]');
  if (menu && botonMenu) {
    menu.classList.add('menu-js');
    botonMenu.hidden = false;
    const fijar = (abierto) => {
      menu.classList.toggle('abierto', abierto);
      botonMenu.setAttribute('aria-expanded', String(abierto));
    };
    botonMenu.addEventListener('click', () => fijar(botonMenu.getAttribute('aria-expanded') !== 'true'));
    menu.addEventListener('keydown', (ev) => {
      if (ev.key === 'Escape' && botonMenu.getAttribute('aria-expanded') === 'true') { fijar(false); botonMenu.focus(); }
    });
    // Un enlace a un ancla de la misma página cierra el menú.
    menu.querySelectorAll('.menu-enlace').forEach((a) => a.addEventListener('click', () => fijar(false)));
  }

  // Cédula de identidad: ayuda visual mientras se escribe (el servidor valida siempre).
  const cedula = document.querySelector('[data-cedula]');
  const nacionalidad = document.querySelector('[data-cedula-nacionalidad]');
  const ayudaCedula = document.querySelector('[data-cedula-ayuda]');
  if (cedula && nacionalidad && ayudaCedula) {
    const textoBase = ayudaCedula.textContent;
    const puntos = (d) => d.replace(/\B(?=(\d{3})+(?!\d))/g, '.');
    const analizar = () => {
      const t = cedula.value.trim().toUpperCase();
      const m = /^([VE])\s?-?\s?(.*)$/.exec(t);
      const nac = m ? m[1] : nacionalidad.value;
      const digitos = (m ? m[2] : t).replace(/\./g, '');
      return { nac, digitos, valida: /^[1-9][0-9]{5,8}$/.test(digitos), soloPermitidos: /^[0-9.]*$/.test(m ? m[2] : t) };
    };
    const pintar = (final) => {
      const a = analizar();
      ayudaCedula.classList.remove('ayuda-ok', 'ayuda-error');
      if (!cedula.value.trim()) { ayudaCedula.textContent = textoBase; cedula.removeAttribute('aria-invalid'); return; }
      if (a.valida) {
        ayudaCedula.textContent = `Se usará: ${a.nac}-${puntos(a.digitos)}`;
        ayudaCedula.classList.add('ayuda-ok');
        cedula.removeAttribute('aria-invalid');
      } else if (!a.soloPermitidos || a.digitos.length > 9 || final) {
        ayudaCedula.textContent = 'Escriba de 6 a 9 dígitos, con o sin puntos (por ejemplo 12.345.678).';
        ayudaCedula.classList.add('ayuda-error');
        if (final) cedula.setAttribute('aria-invalid', 'true');
      } else {
        ayudaCedula.textContent = textoBase;
        cedula.removeAttribute('aria-invalid');
      }
    };
    cedula.addEventListener('input', () => pintar(false));
    nacionalidad.addEventListener('change', () => pintar(false));
    cedula.addEventListener('blur', () => {
      const a = analizar();
      // Normaliza la presentación: el prefijo escrito pasa al selector y el número queda con puntos.
      if (a.valida) { nacionalidad.value = a.nac; cedula.value = puntos(a.digitos); }
      pintar(true);
    });
  }

  // Foco: primer aviso de error o, si no, el campo de código.
  const error = document.querySelector('.aviso[role="alert"]');
  const codigo = document.querySelector('[data-codigo]:not([disabled])');
  if (codigo) { codigo.focus(); codigo.select(); } else if (error) { error.setAttribute('tabindex', '-1'); error.focus(); }
}());
