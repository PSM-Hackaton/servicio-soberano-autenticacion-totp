// Persistencia cifrada de la bóveda TOTP en IndexedDB (sin texto plano en localStorage).
// Cero dependencias externas.

import { encryptVaultData, decryptVaultData } from './totp-core.js';

const DB_NAME = 'totp_soberano_vault_db';
const DB_VERSION = 1;
const STORE_NAME = 'vault';
const VAULT_KEY = 'encrypted_accounts';

/** @returns {Promise<IDBDatabase>} */
function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/** @returns {Promise<any | null>} */
export async function readEnvelope() {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const req = tx.objectStore(STORE_NAME).get(VAULT_KEY);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(req.error);
    tx.oncomplete = () => db.close();
  });
}

/** @param {any} envelope */
async function writeEnvelope(envelope) {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put(envelope, VAULT_KEY);
    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onerror = () => {
      db.close();
      reject(tx.error);
    };
  });
}

export async function hasVault() {
  const env = await readEnvelope();
  return env !== null;
}

/**
 * Crea o sobrescribe la bóveda cifrada con el PIN.
 * @param {Array<{ id: string, issuer: string, account: string, secret: string, algorithm: string, digits: number, period: number, createdAt: string }>} accounts
 * @param {string} pin
 */
export async function saveVaultAccounts(accounts, pin) {
  const envelope = await encryptVaultData({ accounts, updatedAt: new Date().toISOString() }, pin);
  await writeEnvelope(envelope);
}

/**
 * Desbloquea la bóveda con el PIN y retorna las cuentas.
 * @param {string} pin
 */
export async function unlockVaultAccounts(pin) {
  const envelope = await readEnvelope();
  if (!envelope) return null;
  const data = await decryptVaultData(envelope, pin);
  return Array.isArray(data.accounts) ? data.accounts : [];
}

/** Borra completamente la bóveda local del dispositivo. */
export async function wipeVault() {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).delete(VAULT_KEY);
    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onerror = () => {
      db.close();
      reject(tx.error);
    };
  });
}
