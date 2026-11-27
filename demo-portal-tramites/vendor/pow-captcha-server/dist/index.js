/**
 * Cliente de verificación de tokens en el servidor usando la secret_key privada.
 */
export class CaptchaVerifier {
  /**
   * @param {Object} options
   * @param {string} options.secretKey - Llave secreta del sitio (ej. sk_live_... o hex de 32 bytes)
   * @param {string} [options.apiBase='http://localhost:3000/api/captcha'] - URL base del servicio CAPTCHA
   * @param {number} [options.timeoutMs=5000] - Tiempo límite para validar contra el servidor
   */
  constructor({ secretKey, apiBase = 'http://localhost:3000/api/captcha', timeoutMs = 5000 } = {}) {
    if (!secretKey) {
      throw new Error('[CaptchaVerifier] secretKey es obligatoria para validar tokens');
    }
    this.secretKey = secretKey;
    this.apiBase = apiBase.replace(/\/$/, '');
    this.timeoutMs = timeoutMs;
  }

  /**
   * Valida y consume el token emitido por el cliente.
   * @param {string} token - Token de verificación devuelto por el frontend
   * @returns {Promise<{ valid: boolean, error?: string, payload?: object }>}
   */
  async validate(token) {
    if (!token || typeof token !== 'string') {
      return { valid: false, error: 'Token de CAPTCHA no provisto o inválido' };
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const res = await fetch(`${this.apiBase}/validate-token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.secretKey}`,
        },
        body: JSON.stringify({
          token,
          secret_key: this.secretKey,
        }),
        signal: controller.signal,
      });

      clearTimeout(timer);

      const data = await res.json().catch(() => ({}));

      if (!res.ok || !data.valid) {
        return {
          valid: false,
          error: data.error || `Error HTTP ${res.status} al validar token`,
        };
      }

      return {
        valid: true,
        payload: data.payload,
      };
    } catch (err) {
      clearTimeout(timer);
      if (err.name === 'AbortError') {
        return { valid: false, error: 'Tiempo de espera agotado al validar CAPTCHA' };
      }
      return { valid: false, error: `Fallo de conexión con servicio CAPTCHA: ${err.message}` };
    }
  }

  /**
   * Retorna un middleware estándar para Express / Connect.
   * Busca el token en req.body.captcha_token o req.headers['x-captcha-token'].
   */
  middleware({ tokenField = 'captcha_token' } = {}) {
    return async (req, res, next) => {
      const token = req.body?.[tokenField] || req.headers['x-captcha-token'];

      if (!token) {
        return res.status(403).json({
          success: false,
          error: `Campo de verificación '${tokenField}' requerido`,
        });
      }

      const result = await this.validate(token);
      if (!result.valid) {
        return res.status(403).json({
          success: false,
          error: result.error || 'Verificación CAPTCHA fallida',
        });
      }

      req.captcha = result.payload;
      next();
    };
  }
}
