// Adaptador de claves de firma sobre la tabla signing_keys: implementa el objeto `firmas`
// ({ activa, jwks, buscarClave }) que esperan los casos de uso. Lee la base en cada llamada
// (así una rotación se ve al instante) y guarda en memoria las privadas ya descifradas.

import { createPrivateKey } from 'node:crypto';
import { generarParFirma, getPublicJwks } from '../../core/tokens/tokens.js';

const ESTADOS_VERIFICABLES = new Set(['activa', 'solo_verificacion']);

/** Contexto AAD de la clave privada cifrada. @param {string} kid */
export const contextoFirma = (kid) => `signing:${kid}`;

/**
 * Genera un par Ed25519 y lo guarda cifrado (vault.encryptBlob con AAD 'signing:'+kid).
 * No cambia el estado de otras claves: eso lo hace quien rota, dentro de su transacción.
 * @param {{ repos: any, vault: any }} deps
 * @returns {{ kid: string, privateKey: import('node:crypto').KeyObject }}
 */
export function generarYGuardarClave({ repos, vault }) {
  const par = generarParFirma();
  const cifrado = vault.encryptBlob(Buffer.from(par.privatePem, 'utf8'), contextoFirma(par.kid));
  repos.signingKeys.guardar({
    kid: par.kid,
    public_jwk: par.publicJwk,
    private_ct: cifrado.ct,
    private_nonce: cifrado.nonce,
    private_auth_tag: cifrado.authTag,
    key_version: cifrado.keyVersion,
    estado: 'activa',
  });
  return { kid: par.kid, privateKey: par.privateKey };
}

/**
 * Crea el objeto `firmas` respaldado por signing_keys.
 * @param {{ repos: any, vault: any }} deps
 */
export function crearFirmas({ repos, vault }) {
  /** @type {Map<string, import('node:crypto').KeyObject>} */
  const privadas = new Map();

  return {
    /** Clave activa para firmar. Lanza si no existe ninguna (el arranque debe crearla). */
    activa() {
      const fila = repos.signingKeys.activa();
      if (!fila) throw new Error('No hay clave de firma activa');
      let privateKey = privadas.get(fila.kid);
      if (!privateKey) {
        const pem = vault.decryptBlob({
          ct: fila.private_ct, nonce: fila.private_nonce, authTag: fila.private_auth_tag, keyVersion: fila.key_version,
        }, contextoFirma(fila.kid));
        privateKey = createPrivateKey({ key: pem, format: 'pem' });
        pem.fill(0);
        privadas.set(fila.kid, privateKey);
      }
      return { kid: fila.kid, privateKey };
    },
    /** JWKS público: activa + solo_verificacion. */
    jwks: () => getPublicJwks(repos.signingKeys.listarVerificables().map((f) => f.public_jwk)),
    /** JWK público de un kid verificable o null (retiradas y desconocidas no validan). @param {string} kid */
    buscarClave(kid) {
      const fila = repos.signingKeys.buscarPorKid(kid);
      return fila && ESTADOS_VERIFICABLES.has(fila.estado) ? fila.public_jwk : null;
    },
    /** Olvida las privadas en memoria (tras una rotación). */
    recargar() { privadas.clear(); },
    /** Crea la primera clave si la tabla no tiene ninguna activa. @returns {string} kid activo */
    asegurarActiva() {
      const fila = repos.signingKeys.activa();
      return fila ? fila.kid : generarYGuardarClave({ repos, vault }).kid;
    },
  };
}
