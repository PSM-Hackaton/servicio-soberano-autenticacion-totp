# @pow-captcha/server

SDK Backend para validar tokens de verificación Proof-of-Work usando tu **Secret Key**.

## 🚀 Instalación

```bash
npm install @pow-captcha/server
```

---

## 💻 Uso en Node.js / Express

```javascript
import express from 'express';
import { CaptchaVerifier } from '@pow-captcha/server';

const app = express();
app.use(express.json());

const verifier = new CaptchaVerifier({
  secretKey: process.env.CAPTCHA_SECRET_KEY, // Obtenida en tu panel de administración
  apiBase: 'http://localhost:3000/api/captcha',
});

// Opción 1: Verificación manual
app.post('/api/login', async (req, res) => {
  const { email, password, captcha_token } = req.body;

  const check = await verifier.validate(captcha_token);
  if (!check.valid) {
    return res.status(403).json({ error: check.error });
  }

  // Usuario verificado, proceder con autenticación...
  res.json({ success: true });
});

// Opción 2: Middleware automático
app.post('/api/comentario', verifier.middleware(), (req, res) => {
  // Solo se ejecuta si el token fue válido y consumido exitosamente
  res.json({ success: true, userCaptcha: req.captcha });
});
```

---

## 🐍 Uso en Python (FastAPI / Flask / Django)

```python
import requests

def verificar_captcha(token: str, secret_key: str) -> bool:
    r = requests.post(
        "http://localhost:3000/api/captcha/validate-token",
        json={"token": token, "secret_key": secret_key},
        headers={"Authorization": f"Bearer {secret_key}"},
        timeout=5
    )
    return r.status_code == 200 and r.json().get("valid") is True
```

---

## 🐘 Uso en PHP

```php
$data = json_encode([
    'token' => $_POST['captcha_token'],
    'secret_key' => 'tu_secret_key'
]);

$ch = curl_init('http://localhost:3000/api/captcha/validate-token');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);

$response = json_decode(curl_exec($ch), true);
curl_close($ch);

if (!$response['valid']) {
    http_response_code(403);
    die('CAPTCHA inválido');
}
```
