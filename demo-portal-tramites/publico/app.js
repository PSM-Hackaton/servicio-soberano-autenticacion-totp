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

  // Foco: primer aviso de error o, si no, el campo de código.
  const error = document.querySelector('.aviso[role="alert"]');
  const codigo = document.querySelector('[data-codigo]:not([disabled])');
  if (codigo) { codigo.focus(); codigo.select(); } else if (error) { error.setAttribute('tabindex', '-1'); error.focus(); }
}());
