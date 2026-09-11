const DB_NAME = 'fmd-keystore';
const STORE_NAME = 'keys';
const DB_VERSION = 1;

export interface KeyStore {
  rsaEncKey: CryptoKey;
  rsaSigKey: CryptoKey;
}

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => reject(new Error(request.error?.message || 'Failed to open database'));
    request.onsuccess = () => resolve(request.result);

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
  });
}

export async function storeKeys(keys: KeyStore): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.put(keys, 'current');

    request.onerror = () => reject(new Error(request.error?.message || 'Failed to store keys'));
    request.onsuccess = () => resolve();
  });
}

export async function getKeys(): Promise<KeyStore | null> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readonly');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.get('current');

    request.onerror = () => reject(new Error(request.error?.message || 'Failed to get keys'));
    request.onsuccess = () => resolve((request.result as KeyStore | undefined) || null);
  });
}

export async function clearKeys(): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.delete('current');

    request.onerror = () => reject(new Error(request.error?.message || 'Failed to clear keys'));
    request.onsuccess = () => resolve();
  });
}

// ---- Several devices ----
//
// The original store kept one entry under the literal key 'current', which is
// the whole reason this UI could only ever show one phone. Companions are kept
// beside it, keyed by account name, so the existing single-device path is
// untouched and the family view is additive.
//
// Each device's private key is still unwrapped from its own password in this
// browser. The server never sees a plaintext location for any of them.

export async function storeKeysFor(fmdId: string, keys: KeyStore): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readwrite');
    const request = transaction.objectStore(STORE_NAME).put(keys, `device:${fmdId}`);
    request.onerror = () => reject(new Error(request.error?.message || 'Failed to store keys'));
    request.onsuccess = () => resolve();
  });
}

export async function getKeysFor(fmdId: string): Promise<KeyStore | null> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readonly');
    const request = transaction.objectStore(STORE_NAME).get(`device:${fmdId}`);
    request.onerror = () => reject(new Error(request.error?.message || 'Failed to get keys'));
    request.onsuccess = () => resolve((request.result as KeyStore | undefined) || null);
  });
}

export async function deleteKeysFor(fmdId: string): Promise<void> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readwrite');
    const request = transaction.objectStore(STORE_NAME).delete(`device:${fmdId}`);
    request.onerror = () => reject(new Error(request.error?.message || 'Failed to delete keys'));
    request.onsuccess = () => resolve();
  });
}
