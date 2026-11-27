// Rotación de la llave maestra: recifra con la versión activa (MASTER_KEY_VERSION) todo el material
// cifrado con versiones anteriores, semillas TOTP (enrollments), claves privadas de firma
// (signing_keys) y secretos de derivación de user_ref desde la cédula (apps), en una sola transacción. Idempotente: lo que ya está en la versión activa no se toca.

import { contextoFirma } from '../config/firmas.js';

/** Contexto (AAD) del secreto de derivación de user_ref desde la cédula de una app. */
export const contextoCedula = (appId) => `cedula:${appId}`;

/** Recifra un registro; un fallo de descifrado (llave incorrecta o dato alterado) aborta la rotación. */
function recifrar(vault, registro, contexto, descripcion) {
  try {
    return vault.reencrypt(registro, contexto);
  } catch {
    throw new ErrorRotacion(`No se pudo descifrar ${descripcion} con la llave ${registro.keyVersion}`);
  }
}

/** Error de rotación sin datos sensibles en el mensaje. */
export class ErrorRotacion extends Error {
  /** @param {string} mensaje */
  constructor(mensaje) {
    super(mensaje);
    this.name = 'ErrorRotacion';
  }
}

/**
 * @param {{
 *   repos: ReturnType<typeof import('./repositorios.js').crearRepositorios>,
 *   vault: ReturnType<typeof import('../../core/vault/vault.js').crearVault>,
 *   bitacora?: { registrar(e: { actor: string, accion: string, objetivo?: string | null, detalle?: unknown }): any },
 * }} dependencias Con `bitacora`, si hubo cambios se audita en la misma transacción.
 * @returns {{ versionActiva: string, semillas: number, clavesFirma: number, secretosCedula: number }}
 */
export function recifrarConLlaveActiva({ repos, vault, bitacora }) {
  const activa = vault.versionActiva;
  return repos.transaccion(() => {
    const semillas = repos.enrollments.listarFueraDeVersion(activa);
    const claves = repos.signingKeys.listarFueraDeVersion(activa);
    const cedulas = repos.apps.listarCedulaFueraDeVersion?.(activa) ?? [];

    // Todas las versiones de origen deben seguir en el llavero; si falta alguna no se toca nada.
    const faltan = [...new Set([...semillas, ...claves].map((f) => f.key_version).concat(cedulas.map((f) => f.cedula_key_version)))].filter((v) => !vault.tieneVersion(v));
    if (faltan.length > 0) {
      throw new ErrorRotacion(`Faltan en el entorno las llaves de las versiones: ${faltan.join(', ')} (MASTER_KEY_<VERSION>_HEX)`);
    }

    let nSemillas = 0;
    for (const f of semillas) {
      const registro = { ct: f.seed_ct, nonce: f.seed_nonce, authTag: f.seed_auth_tag, keyVersion: f.key_version };
      const n = recifrar(vault, registro, f.id, `el enrolamiento ${f.id}`);
      const ok = repos.enrollments.recifrarSemilla(f.id, {
        seed_ct: n.ct, seed_nonce: n.nonce, seed_auth_tag: n.authTag, key_version: n.keyVersion,
      }, f.key_version);
      if (!ok) throw new ErrorRotacion(`Conflicto al recifrar el enrolamiento ${f.id}: cambió durante la rotación`);
      nSemillas++;
    }

    let nClaves = 0;
    for (const f of claves) {
      const registro = { ct: f.private_ct, nonce: f.private_nonce, authTag: f.private_auth_tag, keyVersion: f.key_version };
      const n = recifrar(vault, registro, contextoFirma(f.kid), `la clave de firma ${f.kid}`);
      const ok = repos.signingKeys.recifrarPrivada(f.kid, {
        private_ct: n.ct, private_nonce: n.nonce, private_auth_tag: n.authTag, key_version: n.keyVersion,
      }, f.key_version);
      if (!ok) throw new ErrorRotacion(`Conflicto al recifrar la clave de firma ${f.kid}: cambió durante la rotación`);
      nClaves++;
    }

    let nCedulas = 0;
    for (const f of cedulas) {
      const registro = { ct: f.cedula_secreto_ct, nonce: f.cedula_secreto_nonce, authTag: f.cedula_secreto_auth_tag, keyVersion: f.cedula_key_version };
      const n = recifrar(vault, registro, contextoCedula(f.id), `el secreto de derivación de la app ${f.id}`);
      if (!repos.apps.recifrarCedula(f.id, n, f.cedula_key_version)) {
        throw new ErrorRotacion(`Conflicto al recifrar el secreto de derivación de la app ${f.id}: cambió durante la rotación`);
      }
      nCedulas++;
    }

    if (bitacora && nSemillas + nClaves + nCedulas > 0) {
      bitacora.registrar({
        actor: 'operador:rotacion', accion: 'llave_maestra.rotada', objetivo: activa,
        detalle: nCedulas > 0 ? { semillas: nSemillas, claves_firma: nClaves, secretos_cedula: nCedulas } : { semillas: nSemillas, claves_firma: nClaves },
      });
    }
    return { versionActiva: activa, semillas: nSemillas, clavesFirma: nClaves, secretosCedula: nCedulas };
  });
}
