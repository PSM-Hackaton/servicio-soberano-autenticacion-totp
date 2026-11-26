// Servicio TOTP FALSO para pruebas de integración (node:http, en memoria).
// Simula el contrato de contracts/openapi.yaml con TOTP real (RFC 6238, SHA-256, 6 dígitos, 30 s),
// JWT EdDSA reales, anti-replay, bloqueo por intentos, idempotencia y fallos inyectables
// (503, lentitud, cortes de conexión). NUNCA usar en producción.
//
// Uso como módulo:   const falso = crearServicioFalso(); const url = await falso.iniciar();
// Uso por consola:   node sdk/testing/servicio-falso.js --puerto 8099

import http from 'node:http';
import {
  createHmac, generateKeyPairSync, randomBytes, randomUUID, sign, createHash,
} from 'node:crypto';
import { fileURLToPath } from 'node:url';

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** @param {Buffer} bytes */
function base32(bytes) {
  let bits = 0; let valor = 0; let salida = '';
  for (const b of bytes) {
    valor = (valor << 8) | b; bits += 8;
    while (bits >= 5) { salida += B32[(valor >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) salida += B32[(valor << (5 - bits)) & 31];
  return salida;
}

/** HOTP RFC 4226 con HMAC-SHA256. */
function hotp(semilla, contador, digitos = 6) {
  const c = Buffer.alloc(8);
  c.writeBigUInt64BE(BigInt(contador));
  const h = createHmac('sha256', semilla).update(c).digest();
  const o = h[h.length - 1] & 0x0f;
  const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 10 ** digitos).padStart(digitos, '0');
}

const paso = (ms, periodo = 30) => Math.floor(ms / 1000 / periodo);

/** Intenta usar el generador QR propio del backend para que la demo muestre un QR escaneable. */
async function cargarQr() {
  try {
    const qr = await import(new URL('../../backend/src/core/qr/qr.js', import.meta.url).href);
    return (texto) => qr.qrToSvg(qr.encodeQr(texto, { nivel: 'M' }), { escala: 5 });
  } catch {
    return () => "<svg xmlns='http://www.w3.org/2000/svg' width='180' height='180'><rect width='180' height='180' fill='#fff'/><text x='24' y='95' font-size='14'>QR de prueba</text></svg>";
  }
}

/**
 * `reloj` gobierna los pasos TOTP, bloqueos y vencimientos de enrolamiento (permite simular el
 * paso del tiempo en pruebas); los JWT usan siempre la hora real para que el integrador los valide.
 * @param {{ clientId?: string, clientSecret?: string, issuer?: string, control?: boolean,
 *   maxFallos?: number, bloqueoSegundos?: number, reloj?: () => number }} [o]
 */
export function crearServicioFalso({
  clientId = 'portal-tramites',
  clientSecret = 'secreto-de-prueba-no-usar-en-produccion',
  issuer = 'https://totp.soberano.local',
  control = false,
  maxFallos = 5,
  bloqueoSegundos = 60,
  reloj = Date.now,
} = {}) {
  /** Fallos inyectables. Modifíquelos en caliente desde las pruebas. */
  const modo = {
    caido: false,          // todas las rutas responden 503
    fallos503: 0,          // las próximas N peticiones responden 503
    retardoMs: 0,          // espera antes de responder (simula lentitud / tiempo agotado)
    retardosPendientes: null, // null: el retardo aplica siempre; N: solo a las próximas N peticiones
    cortes: 0,             // las próximas N peticiones se cortan SIN procesar
    cortesTrasProcesar: 0, // las próximas N se procesan y luego se corta la conexión (respuesta perdida)
    rutasCaidas: [],       // rutas concretas que responden 503 (p. ej. ['/api/v1/tokens/validate'])
    tokenAlterado: false,  // verify devuelve un JWT con los claims manipulados (firma inválida)
  };
  /** Registro de peticiones recibidas (para aserciones). Nunca guarda el secreto ni el código. */
  const registro = [];

  const enrolamientos = new Map(); // id -> { id, userRef, semilla, estado, ultimoPaso, expira, codigos:Set }
  const porUsuario = new Map();    // userRef -> id del enrolamiento activo
  const fallos = new Map();        // userRef -> { n, bloqueadoHasta }
  const idempotencia = new Map();  // clave -> { status, cuerpo }
  const jtiConsumidos = new Set();
  const claves = [];               // { kid, privateKey, jwk }
  rotarClave();

  /** @type {(texto: string) => string} */
  let svgQr = () => '';
  const listoQr = cargarQr().then((f) => { svgQr = f; });

  function rotarClave() {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const { x } = /** @type {any} */ (publicKey.export({ format: 'jwk' }));
    const kid = createHash('sha256').update(x).digest('base64url').slice(0, 22);
    claves.unshift({ kid, privateKey, jwk: { kty: 'OKP', crv: 'Ed25519', kid, use: 'sig', alg: 'EdDSA', x } });
    return kid;
  }

  /** Firma un JWT arbitrario con la clave activa (útil para probar rechazos). */
  function firmarToken(claimsExtra = {}, { kid } = {}) {
    const clave = kid ? claves.find((c) => c.kid === kid) : claves[0];
    const iat = Math.floor(Date.now() / 1000);
    const header = { alg: 'EdDSA', typ: 'JWT', kid: clave.kid };
    const claims = {
      iss: issuer, sub: 'hmac_' + randomBytes(6).toString('hex'), aud: clientId, amr: ['otp'], iat, nbf: iat, exp: iat + 300, jti: randomUUID(), ...claimsExtra,
    };
    const entrada = `${Buffer.from(JSON.stringify(header)).toString('base64url')}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}`;
    return { token: `${entrada}.${sign(null, Buffer.from(entrada), clave.privateKey).toString('base64url')}`, claims, kid: clave.kid };
  }

  /** Código TOTP vigente del usuario (como lo mostraría su autenticador). */
  function codigoPara(userRef, desfasePasos = 0) {
    const id = porUsuario.get(userRef) ?? [...enrolamientos.values()].reverse().find((e) => e.userRef === userRef)?.id;
    const e = id && enrolamientos.get(id);
    return e ? hotp(e.semilla, paso(reloj()) + desfasePasos) : null;
  }

  /** Código vigente de un enrolamiento concreto (p. ej. pendiente de activar). */
  function codigoDeEnrolamiento(id, desfasePasos = 0) {
    const e = enrolamientos.get(id);
    return e ? hotp(e.semilla, paso(reloj()) + desfasePasos) : null;
  }

  const err = (status, error, message, extra = {}) => ({ status, cuerpo: { error, message, ...extra } });
  const GEN = () => err(401, 'VERIFICATION_FAILED', 'No se pudo completar la verificación.');

  /** Comprueba un código en ventana ±1 con anti-replay; devuelve el paso aceptado o null. */
  function comprobar(e, codigo) {
    const actual = paso(reloj());
    for (const d of [0, -1, 1]) {
      const p = actual + d;
      if (p > e.ultimoPaso && hotp(e.semilla, p) === codigo) return { paso: p, deriva: d };
    }
    return null;
  }

  function registrarFallo(userRef) {
    const f = fallos.get(userRef) ?? { n: 0, bloqueadoHasta: 0 };
    f.n += 1;
    if (f.n >= maxFallos) { f.bloqueadoHasta = reloj() + bloqueoSegundos * 1000; f.n = 0; }
    fallos.set(userRef, f);
  }

  function bloqueo(userRef) {
    const f = fallos.get(userRef);
    if (f && f.bloqueadoHasta > reloj()) {
      const s = Math.ceil((f.bloqueadoHasta - reloj()) / 1000);
      return err(429, 'TOO_MANY_REQUESTS', 'Demasiados intentos. Intente más tarde.', { retry_after_seconds: s });
    }
    return null;
  }

  const rutas = {
    'GET /health': () => ({ status: 200, cuerpo: { status: 'ok', timestamp: new Date(reloj()).toISOString(), dbDriver: 'sqlite', activeKeyId: claves[0].kid, heuristicsMode: 'mock' } }),
    'GET /.well-known/jwks.json': () => ({ status: 200, cuerpo: { keys: claves.slice(0, 2).map((c) => c.jwk) } }),

    'POST /api/v1/enrollments': (b) => {
      if (typeof b.user_ref !== 'string' || b.user_ref.length < 1 || b.user_ref.length > 128) return err(400, 'INVALID_REQUEST', 'Solicitud inválida.');
      const id = randomUUID();
      const semilla = randomBytes(32);
      const cuenta = typeof b.account_label === 'string' ? b.account_label : b.user_ref;
      const params = new URLSearchParams({ secret: base32(semilla), issuer: 'ServicioSoberanoTOTP', algorithm: 'SHA256', digits: '6', period: '30' });
      const uri = `otpauth://totp/${encodeURIComponent('ServicioSoberanoTOTP')}:${encodeURIComponent(cuenta)}?${params}`;
      enrolamientos.set(id, { id, userRef: b.user_ref, semilla, estado: 'pendiente', ultimoPaso: -1, expira: reloj() + 600000, codigos: new Set() });
      return {
        status: 201,
        cuerpo: {
          enrollment_id: id, estado: 'pendiente', algoritmo: 'SHA256', digitos: 6, periodo: 30,
          otpauth_uri: uri, qr_svg: svgQr(uri), expires_at: new Date(reloj() + 600000).toISOString(),
        },
      };
    },

    'POST /api/v1/enrollments/:id/activate': (b, { id }) => {
      const e = enrolamientos.get(id);
      if (!e || e.estado !== 'pendiente' || e.expira < reloj() || typeof b.code !== 'string') return GEN();
      const ok = comprobar(e, b.code);
      if (!ok) return GEN();
      e.ultimoPaso = ok.paso;
      e.estado = 'activo';
      const anterior = porUsuario.get(e.userRef);
      if (anterior && enrolamientos.get(anterior)) enrolamientos.get(anterior).estado = 'revocado';
      porUsuario.set(e.userRef, id);
      const codigos = Array.from({ length: 10 }, () => {
        const t = base32(randomBytes(5)).slice(0, 8);
        return `${t.slice(0, 4)}-${t.slice(4)}`;
      });
      e.codigos = new Set(codigos);
      return { status: 200, cuerpo: { enrollment_id: id, estado: 'activo', activated_at: new Date(reloj()).toISOString(), recovery_codes: codigos } };
    },

    'POST /api/v1/verify': (b) => {
      if (typeof b.user_ref !== 'string' || typeof b.code !== 'string' || !/^\d{6,8}$/.test(b.code)) return err(400, 'INVALID_REQUEST', 'Solicitud inválida.');
      const bloq = bloqueo(b.user_ref);
      if (bloq) return bloq;
      const e = enrolamientos.get(porUsuario.get(b.user_ref));
      if (!e || e.estado !== 'activo') { registrarFallo(b.user_ref); return GEN(); }
      const ok = comprobar(e, b.code);
      if (!ok) { registrarFallo(b.user_ref); return bloqueo(b.user_ref) ?? GEN(); }
      e.ultimoPaso = ok.paso;
      fallos.delete(b.user_ref);
      const sub = 'hmac_' + createHmac('sha256', 'pimienta-falsa').update(b.user_ref).digest('hex').slice(0, 16);
      const firmado = firmarToken({ sub });
      const { claims, kid } = firmado;
      let { token } = firmado;
      if (modo.tokenAlterado) {
        const [h, , f] = token.split('.');
        token = `${h}.${Buffer.from(JSON.stringify({ ...claims, sub: 'hmac_otra_persona' })).toString('base64url')}.${f}`;
      }
      return {
        status: 200,
        cuerpo: {
          verified: true, token, jti: claims.jti, kid, expires_at: new Date(claims.exp * 1000).toISOString(), drift_steps: ok.deriva,
          risk: { level: 'LOW' },
        },
      };
    },

    'POST /api/v1/tokens/validate': (b) => {
      const partes = typeof b.token === 'string' ? b.token.split('.') : [];
      if (partes.length !== 3) return { status: 200, cuerpo: { valid: false, reason: 'formato' } };
      let header; let claims;
      try {
        header = JSON.parse(Buffer.from(partes[0], 'base64url').toString());
        claims = JSON.parse(Buffer.from(partes[1], 'base64url').toString());
      } catch { return { status: 200, cuerpo: { valid: false, reason: 'formato' } }; }
      const clave = claves.find((c) => c.kid === header.kid);
      if (!clave) return { status: 200, cuerpo: { valid: false, reason: 'kid' } };
      const esperada = sign(null, Buffer.from(`${partes[0]}.${partes[1]}`), clave.privateKey).toString('base64url');
      if (esperada !== partes[2]) return { status: 200, cuerpo: { valid: false, reason: 'firma' } };
      if (claims.exp * 1000 <= Date.now()) return { status: 200, cuerpo: { valid: false, reason: 'exp' } };
      if (jtiConsumidos.has(claims.jti)) return { status: 200, cuerpo: { valid: false, reason: 'jti_consumido' } };
      if (b.consume_jti !== false) jtiConsumidos.add(claims.jti);
      return { status: 200, cuerpo: { valid: true, sub: claims.sub, aud: claims.aud, jti: claims.jti, kid: header.kid, amr: claims.amr, exp: claims.exp } };
    },

    'POST /api/v1/enrollments/:id/resync': (b, { id }) => {
      const e = enrolamientos.get(id);
      if (!e || e.estado !== 'activo') return GEN();
      const actual = paso(reloj());
      for (let d = -10; d <= 10; d++) {
        if (hotp(e.semilla, actual + d) === b.code_1 && hotp(e.semilla, actual + d + 1) === b.code_2) {
          e.ultimoPaso = actual + d + 1;
          return { status: 200, cuerpo: { resynced: true, drift_steps: d + 1 } };
        }
      }
      return GEN();
    },

    'POST /api/v1/recovery': (b) => {
      const e = enrolamientos.get(porUsuario.get(b.user_ref));
      const codigo = typeof b.recovery_code === 'string' ? b.recovery_code.toUpperCase().trim() : '';
      if (!e || e.estado !== 'activo' || !e.codigos.has(codigo)) { registrarFallo(b.user_ref ?? ''); return GEN(); }
      e.codigos.delete(codigo);
      e.estado = 'requiere_reenrolar';
      porUsuario.delete(b.user_ref);
      return { status: 200, cuerpo: { recovered: true, must_reenroll: true, remaining_codes: e.codigos.size } };
    },

    'DELETE /api/v1/enrollments/:id': (_b, { id }) => {
      const e = enrolamientos.get(id);
      if (!e) return err(404, 'NOT_FOUND', 'No encontrado.');
      e.estado = 'revocado';
      if (porUsuario.get(e.userRef) === id) porUsuario.delete(e.userRef);
      return { status: 200, cuerpo: { enrollment_id: id, estado: 'revocado', revoked_at: new Date(reloj()).toISOString() } };
    },
  };

  function resolver(metodo, ruta) {
    for (const [clave, fn] of Object.entries(rutas)) {
      const [m, plantilla] = clave.split(' ');
      if (m !== metodo) continue;
      const a = plantilla.split('/'); const r = ruta.split('/');
      if (a.length !== r.length) continue;
      const params = {};
      if (a.every((s, i) => (s.startsWith(':') ? ((params[s.slice(1)] = decodeURIComponent(r[i])), true) : s === r[i]))) return { fn, params };
    }
    return null;
  }

  const espera = (ms) => new Promise((r) => setTimeout(r, ms));

  const servidor = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://falso');
    const trozos = [];
    for await (const t of req) trozos.push(t);
    const texto = Buffer.concat(trozos).toString('utf8');
    let cuerpo = {};
    try { cuerpo = texto ? JSON.parse(texto) : {}; } catch { cuerpo = null; }

    const responder = ({ status, cuerpo: c, cabeceras = {} }) => {
      if (res.destroyed) return;
      res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...cabeceras });
      res.end(JSON.stringify(c));
    };

    // Canal de control (solo en modo CLI / demo; nunca existe en el servicio real).
    if (control && url.pathname.startsWith('/__falso/')) {
      if (req.method === 'POST' && url.pathname === '/__falso/modo') { Object.assign(modo, cuerpo ?? {}); return responder({ status: 200, cuerpo: modo }); }
      if (req.method === 'GET' && url.pathname === '/__falso/codigo') {
        const desfase = Number(url.searchParams.get('desfase') ?? 0) || 0;
        return responder({ status: 200, cuerpo: { code: codigoPara(url.searchParams.get('user_ref') ?? '', desfase) } });
      }
      if (req.method === 'POST' && url.pathname === '/__falso/rotar') return responder({ status: 200, cuerpo: { kid: rotarClave() } });
      return responder({ status: 404, cuerpo: { error: 'NOT_FOUND', message: 'No encontrado.' } });
    }

    const entrada = {
      metodo: req.method, ruta: url.pathname, idempotencyKey: req.headers['idempotency-key'] ?? null,
      autenticado: req.headers['x-client-id'] === clientId && req.headers['x-client-secret'] === clientSecret, en: reloj(),
      // IP del usuario final que envía el integrador (dato de red, no secreto): para aserciones.
      clientIp: cuerpo && typeof cuerpo.client_ip === 'string' ? cuerpo.client_ip : null,
    };
    registro.push(entrada);

    if (modo.retardoMs > 0) {
      if (modo.retardosPendientes == null) await espera(modo.retardoMs);
      else if (modo.retardosPendientes > 0) { modo.retardosPendientes -= 1; await espera(modo.retardoMs); }
    }
    if (modo.cortes > 0) { modo.cortes -= 1; req.socket.destroy(); return; }
    if (modo.caido || modo.fallos503 > 0 || modo.rutasCaidas.includes(url.pathname)) {
      if (!modo.caido && !modo.rutasCaidas.includes(url.pathname)) modo.fallos503 -= 1;
      return responder({ status: 503, cuerpo: { error: 'SERVICE_UNAVAILABLE', message: 'Servicio no disponible temporalmente.' }, cabeceras: { 'Retry-After': '5' } });
    }
    if (cuerpo === null) return responder(err(400, 'INVALID_REQUEST', 'Solicitud inválida.'));

    const r = resolver(req.method, url.pathname);
    if (!r) return responder(err(404, 'NOT_FOUND', 'No encontrado.'));
    const publica = url.pathname === '/health' || url.pathname === '/.well-known/jwks.json';
    if (!publica && !entrada.autenticado) return responder(err(401, 'UNAUTHORIZED', 'Credenciales inválidas.'));

    // Idempotencia: misma clave + misma ruta => misma respuesta, sin volver a procesar.
    const claveIdem = entrada.idempotencyKey && req.method !== 'GET' ? `${req.method} ${url.pathname} ${entrada.idempotencyKey}` : null;
    let resultado = claveIdem ? idempotencia.get(claveIdem) : undefined;
    if (resultado) entrada.repetida = true;
    else {
      await listoQr;
      resultado = r.fn(cuerpo, r.params);
      if (claveIdem && resultado.status < 500) idempotencia.set(claveIdem, resultado);
    }
    if (modo.cortesTrasProcesar > 0) { modo.cortesTrasProcesar -= 1; req.socket.destroy(); return; }
    responder(resultado);
  });

  return {
    modo,
    registro,
    clientId,
    clientSecret,
    issuer,
    codigoPara,
    codigoDeEnrolamiento,
    firmarToken,
    rotarClave,
    jwks: () => ({ keys: claves.slice(0, 2).map((c) => c.jwk) }),
    enrolamientos,
    /** @returns {Promise<string>} URL base */
    async iniciar(puerto = 0, host = '127.0.0.1') {
      await listoQr;
      await new Promise((r) => servidor.listen(puerto, host, r));
      const { port } = /** @type {any} */ (servidor.address());
      return `http://${host === '0.0.0.0' ? '127.0.0.1' : host}:${port}`;
    },
    detener() {
      servidor.closeAllConnections?.();
      return new Promise((r) => servidor.close(() => r(undefined)));
    },
  };
}

// ---------- CLI ----------
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const i = process.argv.indexOf('--puerto');
  const puerto = i > 0 ? Number(process.argv[i + 1]) : 8099;
  const falso = crearServicioFalso({ control: true });
  const url = await falso.iniciar(puerto);
  process.stdout.write(
    `Servicio TOTP FALSO escuchando en ${url}\n`
    + `  X-Client-Id:     ${falso.clientId}\n`
    + `  X-Client-Secret: ${falso.clientSecret}\n`
    + `  JWT iss:         ${falso.issuer}\n`
    + '  Control: POST /__falso/modo {"caido":true}, GET /__falso/codigo?user_ref=…\n',
  );
}
