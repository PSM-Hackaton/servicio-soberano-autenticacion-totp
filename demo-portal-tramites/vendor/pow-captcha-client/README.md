# @pow-captcha/client

SDK cliente para integrar la protección Proof-of-Work (PoW) en cualquier formulario o aplicación frontend (Vanilla JS, React, Vue, Svelte o HTML puro).

## 🚀 Instalación

```bash
npm install @pow-captcha/client
```

O vía script directo en HTML:

```html
<script type="module" src="https://tu-dominio.com/packages/client-sdk/dist/index.js"></script>
```

---

## 💻 Uso en HTML Directo

```html
<form id="mi-formulario" action="/registro" method="POST">
  <input type="email" name="email" placeholder="tu@email.com" required />

  <!-- Contenedor del widget con tu Site Key -->
  <div class="pow-captcha" data-sitekey="site_tu_llave_publica"></div>

  <input type="hidden" name="captcha_token" id="captcha_token" />
  <button type="submit" id="btn-submit" disabled>Registrarse</button>
</form>

<script type="module">
  import { PowCaptchaClient } from './dist/index.js';

  const captcha = new PowCaptchaClient('.pow-captcha', {
    siteKey: 'site_tu_llave_publica',
    apiBase: 'http://localhost:3000/api/captcha',
    onVerified(token) {
      document.getElementById('captcha_token').value = token;
      document.getElementById('btn-submit').disabled = false;
    },
    onError(err) {
      console.error('Error al resolver CAPTCHA:', err);
    }
  });
</script>
```

---

## ⚛️ Uso en React / Next.js

```jsx
import { useEffect, useRef, useState } from 'react';
import { PowCaptchaClient } from '@pow-captcha/client';

export function RegistroForm() {
  const containerRef = useRef(null);
  const [token, setToken] = useState(null);

  useEffect(() => {
    if (!containerRef.current) return;

    const captcha = new PowCaptchaClient(containerRef.current, {
      siteKey: process.env.NEXT_PUBLIC_CAPTCHA_SITE_KEY,
      apiBase: 'https://api.tu-dominio.com/api/captcha',
      onVerified: (t) => setToken(t),
    });

    return () => captcha.reset();
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    await fetch('/api/registro', {
      method: 'POST',
      body: JSON.stringify({ email, captcha_token: token }),
    });
  };

  return (
    <form onSubmit={handleSubmit}>
      <input type="email" />
      <div ref={containerRef} />
      <button type="submit" disabled={!token}>Enviar</button>
    </form>
  );
}
```
