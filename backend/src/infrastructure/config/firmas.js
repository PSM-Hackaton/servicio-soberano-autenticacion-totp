// Llavero de firma Ed25519 para JWT MFA, respaldado por la tabla signing_keys.
// Las claves privadas se guardan cifradas con la bóveda (AES-256-GCM, contexto 'signing:<kid>').

import { createPrivateKey } from 'node:crypto';

import { generarParFirma, getPublicJwks } from '../../core/tokens/tokens.js';

/** @param {string} kid */
export const contextoFirma = (kid) => `signing:${kid}`;

/**
 * @param {{
 *   repos: { signingKeys: any, transaccion?: (fn: () => any) => any },
 *   vault: { encryptBlob: Function, decryptBlob: Function },
 *   generar?: typeof generarParFirma,
 * }} dependencias
 */
export function crearFirmas({ repos, vault, generar = generarParFirma }) {
  if (!repos?.signingKeys) throw new Error('Se requiere repos.signingKeys');
  if (!vault) throw new Error('Se requiere la bóveda');
  const claves = repos.signingKeys;
  const enTransaccion = (fn) => (typeof repos.transaccion === 'function' ? repos.transaccion(fn) : fn());

  /** @type {{ kid: string, privateKey: import('node:crypto').KeyObject } | null} */
  let activa = null;
  /** @type {Map<string, any>} kid → JWK público (activa + solo_verificacion) */
  let publicas = new Map();

  /** Genera un par nuevo, cifra la privada y lo guarda con el estado indicado. */
  function generarYGuardar(estado = 'activa') {
    const par = generar();
    const pem = Buffer.from(par.privatePem, 'utf8');
    try {
      const reg = vault.encryptBlob(pem, contextoFirma(par.kid));
      claves.guardar({
        kid: par.kid,
        public_jwk: par.publicJwk,
        private_ct: reg.ct,
        private_nonce: reg.nonce,
        private_auth_tag: reg.authTag,
        key_version: reg.keyVersion,
        estado,
      });
    } finally {
      pem.fill(0);
    }
    return par;
  }

  /** Descifra la clave privada de una fila de signing_keys. */
  function descifrar(fila) {
    const pem = vault.decryptBlob({
      ct: fila.private_ct, nonce: fila.private_nonce, authTag: fila.private_auth_tag, keyVersion: fila.key_version,
    }, contextoFirma(fila.kid));
    try {
      return createPrivateKey({ key: pem, format: 'pem' });
    } finally {
      pem.fill(0);
    }
  }

  /** Relee la base: clave activa (creándola si no hay ninguna) y claves verificables. */
  function recargar() {
    let fila = claves.activa();
    if (!fila) {
      enTransaccion(() => {
        if (!claves.activa()) generarYGuardar('activa');
      });
      fila = claves.activa();
    }
    if (!fila) throw new Error('No se pudo establecer una clave de firma activa');
    activa = { kid: fila.kid, privateKey: descifrar(fila) };
    publicas = new Map(claves.listarVerificables().map((f) => [f.kid, { ...f.public_jwk, kid: f.kid }]));
    publicas.set(fila.kid, { ...fila.public_jwk, kid: fila.kid });
    return api;
  }

  /**
   * Rota la clave: crea una nueva activa y deja la anterior en solo_verificacion (ventana de gracia).
   * @returns {{ new_kid: string, previous_kid: string | null, rotated_at: string }}
   */
  function rotar() {
    const rotadaEn = new Date().toISOString();
    const resultado = enTransaccion(() => {
      const previa = claves.activa();
      if (previa) claves.cambiarEstado(previa.kid, 'solo_verificacion', rotadaEn);
      const nueva = generarYGuardar('activa');
      return { new_kid: nueva.kid, previous_kid: previa?.kid ?? null, rotated_at: rotadaEn };
    });
    recargar();
    return resultado;
  }

  const api = {
    /** Clave de firma vigente. */
    activa() {
      if (!activa) recargar();
      return /** @type {{ kid: string, privateKey: import('node:crypto').KeyObject }} */ (activa);
    },
    /** JWKS público (RFC 7517): clave activa y claves en ventana de gracia. */
    jwks() {
      if (!activa) recargar();
      return getPublicJwks([...publicas.values()]);
    },
    /**
     * JWK público por kid (para verifyMfaJwt). Si no está en caché se consulta la base,
     * por si otra parte del sistema rotó la clave; las retiradas no se aceptan.
     * @param {string} kid
     */
    buscarClave(kid) {
      if (typeof kid !== 'string' || kid.length === 0 || kid.length > 128) return null;
      if (publicas.has(kid)) return publicas.get(kid);
      const fila = claves.buscarPorKid(kid);
      if (!fila || fila.estado === 'retirada') return null;
      const jwk = { ...fila.public_jwk, kid: fila.kid };
      publicas.set(kid, jwk);
      return jwk;
    },
    recargar,
    rotar,
    /** kid activo (para /health). */
    get kidActivo() {
      return activa?.kid ?? null;
    },
  };
  return api;
}
