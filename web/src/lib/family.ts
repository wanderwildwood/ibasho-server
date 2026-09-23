import { create } from 'zustand';
import type { Location } from '@/lib/api';
import {
  base64Encode,
  CRYPTO_PROTO_V1,
  CRYPTO_PROTO_V2,
  decryptData,
  hashPasswordForLogin,
  unwrapPrivateKey,
  type PasswordHashResult,
} from '@/lib/crypto';
import {
  decryptDataV2,
  decryptMasterKey,
  deriveAuthKeyAndPreMasterKey,
  deriveKeks,
} from '@/lib/cryptov2';
import type { CryptoKeysV1, CryptoKeysV2 } from '@/lib/keystore';
import { useStore } from '@/lib/store';

// The other devices on the map: accounts on this same server whose owners gave you their
// password. Nothing here touches the main login. Each device keeps its own session and keys,
// and a device whose session runs out logs itself back in; it never logs you out.
//
// The list outlives a log-out, but locked. It is kept in localStorage under your account's
// name, encrypted with a key made from *your* password, and it holds each device's name, id
// and password: the password because it is the only thing that can rebuild a device's keys
// once they have been thrown away. Logging out, or a session running out, drops the key and
// the working copies; logging back in makes the key again and brings the devices back without
// asking for them. Someone else logging in on the same browser has a different name and a
// different password, and cannot open it. Deleting your account deletes it.
//
// While unlocked, each device's keys (non-extractable CryptoKeys, as upstream keeps the main
// account's), session token and log-in proof sit in IndexedDB, so the map does not re-derive
// them on every visit. The proof is the password hash the server checks at log-in; a session
// that runs out is renewed with it, without touching the password.

const BUNDLE_PREFIX = 'ibasho-family:';
const LEGACY_LIST_KEY = 'ibasho-family';
const DB_NAME = 'ibasho-family';
const STORE_NAME = 'devices';
const WRAP_STORE = 'wrap';
const ONE_WEEK_SECONDS = 7 * 24 * 60 * 60;
// Deliberately slow: this is the lock on a list of other people's passwords.
const PBKDF2_ITERATIONS = 600_000;

export interface FamilyDevice {
  fmdId: string;
  name: string;
  protoVersion: number;
}

interface StoredDevice extends FamilyDevice {
  password: string;
}

interface DeviceSecrets {
  keysV1: CryptoKeysV1 | null;
  keysV2: CryptoKeysV2 | null;
  // v1: the password hash string. v2: K_auth, base64.
  proof: string;
  sessionToken: string;
}

export interface DeviceStatus {
  location: Location | null;
  // When the location was fetched, not when it was recorded.
  fetchedAt: number | null;
  error: string | null;
  // The stored proof was refused: the password has changed. Automatic log-in stops here,
  // because the server locks an account after a handful of failures.
  needsPassword: boolean;
  loading: boolean;
}

interface FamilyState {
  devices: FamilyDevice[];
  // True until the list has been opened with your password (or your remembered key).
  locked: boolean;
  // A remembered session with no remembered key, from before lists were kept: only logging
  // in again, with the password, can open the list.
  needsLogin: boolean;
  status: Record<string, DeviceStatus>;
  // Set when a device is picked in the list; the map pans to it.
  focus: { fmdId: string; at: number } | null;
}

export const useFamily = create<FamilyState>()(() => ({
  devices: [],
  locked: true,
  needsLogin: false,
  status: {},
  focus: null,
}));

// Whose list is open, the key that opens it, and the list itself. Memory only.
let owner: string | null = null;
let wrapKey: CryptoKey | null = null;
let stored: StoredDevice[] = [];
// Set while the login form is opening the list, so a restore that finds no key meanwhile
// does not report the list as out of reach.
let unlocking = false;

function readList(): StoredDevice[] {
  return stored;
}

async function writeList(next: StoredDevice[]) {
  if (!owner || !wrapKey) throw new Error('Log in again first, so the list can be kept locked');
  localStorage.setItem(BUNDLE_PREFIX + owner, await seal(wrapKey, owner, next));
  stored = next;
  useFamily.setState({ devices: next.map(({ password: _, ...d }) => d) });
}

// --- The lock -------------------------------------------------------------------------------

const enc = new TextEncoder();

async function deriveWrapKey(fmdId: string, password: string): Promise<CryptoKey> {
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, [
    'deriveKey',
  ]);
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: enc.encode('whereabouts-family|' + fmdId),
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// The owner's name is bound in as associated data, so a list cannot be moved between names.
async function seal(key: CryptoKey, fmdId: string, list: StoredDevice[]): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: enc.encode(fmdId) },
    key,
    enc.encode(JSON.stringify(list))
  );
  return base64Encode(new Uint8Array([...iv, ...new Uint8Array(ct)]));
}

async function unseal(key: CryptoKey, fmdId: string, sealed: string): Promise<StoredDevice[]> {
  const bytes = Uint8Array.from(atob(sealed), (c) => c.charCodeAt(0));
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: bytes.slice(0, 12), additionalData: enc.encode(fmdId) },
    key,
    bytes.slice(12)
  );
  return JSON.parse(new TextDecoder().decode(plain)) as StoredDevice[];
}

async function openList(fmdId: string, key: CryptoKey) {
  owner = fmdId;
  wrapKey = key;

  const sealed = localStorage.getItem(BUNDLE_PREFIX + fmdId);
  let list: StoredDevice[] = [];
  if (sealed) {
    try {
      list = await unseal(key, fmdId, sealed);
    } catch {
      // Your password has changed since the list was sealed. It stays where it is, unread,
      // rather than being thrown away on a guess.
      list = [];
    }
  }
  // An earlier version kept a plain list, without passwords. Its devices come across and keep
  // working on the keys already in this browser; once those are gone, each asks for its
  // password one time, and from then on is kept like the rest.
  const legacy = readLegacyList().filter((d) => !list.some((l) => l.fmdId === d.fmdId));
  stored = [...list, ...legacy.map((d) => ({ ...d, password: '' }))];
  if (legacy.length > 0)
    localStorage.setItem(BUNDLE_PREFIX + fmdId, await seal(key, fmdId, stored));
  localStorage.removeItem(LEGACY_LIST_KEY);
  list = stored;

  useFamily.setState({
    devices: list.map(({ password: _, ...d }) => d),
    locked: false,
    needsLogin: false,
  });
  await refreshAll();
}

function readLegacyList(): FamilyDevice[] {
  try {
    const raw = localStorage.getItem(LEGACY_LIST_KEY);
    return raw ? (JSON.parse(raw) as FamilyDevice[]) : [];
  } catch {
    return [];
  }
}

/** Called by the login form, which is the one place your password is in hand. */
export async function unlockFamily(fmdId: string, password: string, remember: boolean) {
  unlocking = true;
  try {
    const key = await deriveWrapKey(fmdId, password);
    if (remember) {
      await withStore<void>('readwrite', (s) => s.put(key, fmdId), WRAP_STORE);
    }
    await openList(fmdId, key);
  } finally {
    unlocking = false;
  }
}

/** A remembered session comes back without a password; its remembered key opens the list. */
async function restoreFamily(fmdId: string) {
  if (owner === fmdId && wrapKey) return;
  const key = await withStore<CryptoKey | undefined>('readonly', (s) => s.get(fmdId), WRAP_STORE);
  if (key) await openList(fmdId, key);
  else if (!unlocking) useFamily.setState({ needsLogin: true });
}

/** Logged out, or the session ran out: keep the sealed list, drop everything that opens it. */
export async function lockFamily() {
  owner = null;
  wrapKey = null;
  stored = [];
  useFamily.setState({ devices: [], status: {}, focus: null, locked: true, needsLogin: false });
  await withStore<void>('readwrite', (s) => s.clear(), WRAP_STORE);
  await clearSecrets();
}

// Follow the main login: open the list when someone is logged in, lock it when they are not.
useStore.subscribe((state, prev) => {
  const id = state.userData?.fmdId;
  if (id && id !== prev.userData?.fmdId) void restoreFamily(id);
  if (prev.isLoggedIn && !state.isLoggedIn) void lockFamily();
});
{
  const id = useStore.getState().userData?.fmdId;
  if (id) void restoreFamily(id);
}

const NO_STATUS: DeviceStatus = {
  location: null,
  fetchedAt: null,
  error: null,
  needsPassword: false,
  loading: false,
};

function setStatus(fmdId: string, patch: Partial<DeviceStatus>) {
  useFamily.setState((s) => ({
    status: { ...s.status, [fmdId]: { ...NO_STATUS, ...s.status[fmdId], ...patch } },
  }));
}

// --- IndexedDB ------------------------------------------------------------------------------

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 2);
    request.onerror = () => reject(new Error(request.error?.message || 'Failed to open database'));
    request.onsuccess = () => resolve(request.result);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) {
        request.result.createObjectStore(STORE_NAME);
      }
      if (!request.result.objectStoreNames.contains(WRAP_STORE)) {
        request.result.createObjectStore(WRAP_STORE);
      }
    };
  });
}

async function withStore<T>(
  mode: IDBTransactionMode,
  op: (store: IDBObjectStore) => IDBRequest,
  storeName: string = STORE_NAME
): Promise<T> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const request = op(db.transaction(storeName, mode).objectStore(storeName));
    request.onerror = () => reject(new Error(request.error?.message || 'Key storage failed'));
    request.onsuccess = () => resolve(request.result as T);
  });
}

const putSecrets = (fmdId: string, secrets: DeviceSecrets) =>
  withStore<void>('readwrite', (s) => s.put(secrets, fmdId));

const getSecrets = (fmdId: string) =>
  withStore<DeviceSecrets | undefined>('readonly', (s) => s.get(fmdId));

const deleteSecrets = (fmdId: string) => withStore<void>('readwrite', (s) => s.delete(fmdId));

const clearSecrets = () => withStore<void>('readwrite', (s) => s.clear());

// --- Requests -------------------------------------------------------------------------------

class AuthError extends Error {
  constructor(public status: number) {
    super(status === 403 ? 'Wrong password' : 'Session expired');
  }
}

// Upstream's request helpers log the main account out on a 401. A device's expired session
// must not do that, so these requests go through here instead.
async function send<T>(method: string, url: string, body: object | null, token?: string) {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const response = await fetch(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : null,
  });
  const text = await response.text();

  if (response.status === 401 || response.status === 403) throw new AuthError(response.status);
  if (response.status === 404) throw new Error('No such account on this server');
  if (!response.ok) throw new Error(text || `Request failed (${response.status})`);

  return (text ? JSON.parse(text) : {}) as T;
}

// Same worker the login form uses, so hashing does not freeze the page.
function hashInWorker(
  protoVersion: number,
  fmdId: string,
  password: string,
  salt64: string
): Promise<PasswordHashResult> {
  if (!window.Worker) return hashPasswordForLogin(protoVersion, fmdId, password, salt64);

  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('../workers/passwordHashing.ts', import.meta.url), {
      type: 'module',
    });
    worker.onmessage = (ev) => {
      resolve(ev.data as PasswordHashResult);
      worker.terminate();
    };
    worker.onerror = (err) => {
      reject(new Error(err.message));
      worker.terminate();
    };
    worker.postMessage([protoVersion, fmdId, password, salt64]);
  });
}

async function getSalt(fmdId: string): Promise<[string, number]> {
  const r = await send<{ salt64: string; protoVersion: number }>(
    'GET',
    `api/v2/account/${encodeURIComponent(fmdId)}/salt`,
    null
  );
  return [r.salt64, r.protoVersion];
}

// Log in with a stored or fresh proof and return a session token.
async function requestToken(fmdId: string, protoVersion: number, proof: string) {
  if (protoVersion === CRYPTO_PROTO_V2) {
    const r = await send<{ accessToken: string }>('POST', 'api/v2/account/login', {
      username: fmdId,
      passwordHash64: proof,
      sessionDurationSeconds: ONE_WEEK_SECONDS,
    });
    return r.accessToken;
  }
  const r = await send<{ Data: string }>('PUT', 'api/v1/requestAccess', {
    IDT: fmdId,
    Data: proof,
    SessionDurationSeconds: ONE_WEEK_SECONDS,
  });
  return r.Data;
}

// --- Adding and removing --------------------------------------------------------------------

// A full log-in with the password: returns the keys and the proof to keep. Stores nothing.
async function logIn(
  fmdId: string,
  password: string
): Promise<{ protoVersion: number; secrets: DeviceSecrets }> {
  const [salt64, protoVersion] = await getSalt(fmdId);
  if (!salt64) throw new Error('No such account on this server');

  const hash = await hashInWorker(protoVersion, fmdId, password, salt64);
  let secrets: DeviceSecrets;

  if (protoVersion === CRYPTO_PROTO_V2) {
    const pwk = hash as Uint8Array<ArrayBuffer>;
    const [authKey, preMasterKey] = await deriveAuthKeyAndPreMasterKey(fmdId, pwk.buffer);
    const r = await send<{ accessToken: string; encMasterKey64: string }>(
      'POST',
      'api/v2/account/login',
      {
        username: fmdId,
        passwordHash64: base64Encode(authKey),
        sessionDurationSeconds: ONE_WEEK_SECONDS,
      }
    );
    const [masterKey] = await decryptMasterKey(fmdId, preMasterKey, r.encMasterKey64);
    const [cmdKek, locationKek, pictureKek] = await deriveKeks(fmdId, masterKey);
    secrets = {
      keysV1: null,
      keysV2: { cmdKek, locationKek, pictureKek },
      proof: base64Encode(authKey),
      sessionToken: r.accessToken,
    };
  } else if (protoVersion === CRYPTO_PROTO_V1) {
    const proof = hash as string;
    const sessionToken = await requestToken(fmdId, CRYPTO_PROTO_V1, proof);
    const wrapped = await send<{ Data: string }>('PUT', 'api/v1/key', {
      IDT: sessionToken,
      Data: 'unused',
    });
    const { rsaEncKey, rsaSigKey } = await unwrapPrivateKey(password, wrapped.Data);
    secrets = { keysV1: { rsaEncKey, rsaSigKey }, keysV2: null, proof, sessionToken };
  } else {
    throw new Error(`Unknown protocol version ${protoVersion}`);
  }

  return { protoVersion, secrets };
}

export async function addDevice(fmdId: string, password: string, name: string): Promise<void> {
  fmdId = fmdId.trim();
  if (!wrapKey) throw new Error('Log in again first, so the list can be kept locked');
  if (readList().some((d) => d.fmdId === fmdId)) throw new Error('That device is already here');

  const { protoVersion, secrets } = await logIn(fmdId, password);
  await putSecrets(fmdId, secrets);
  await writeList([...readList(), { fmdId, name: name.trim() || fmdId, protoVersion, password }]);
  await refreshDevice(fmdId);
}

// A device whose password changed gets the new one. The old keys stay until the new
// password has actually logged in, so a mistyped one loses nothing.
export async function reenterPassword(fmdId: string, password: string): Promise<void> {
  const { protoVersion, secrets } = await logIn(fmdId, password);
  await putSecrets(fmdId, secrets);
  await writeList(
    readList().map((d) => (d.fmdId === fmdId ? { ...d, protoVersion, password } : d))
  );
  setStatus(fmdId, { needsPassword: false, error: null });
  await refreshDevice(fmdId);
}

export async function removeDevice(fmdId: string): Promise<void> {
  await deleteSecrets(fmdId);
  await writeList(readList().filter((d) => d.fmdId !== fmdId));
  useFamily.setState((s) => {
    const status = { ...s.status };
    delete status[fmdId];
    return { status };
  });
}

// Deleting your account deletes your list with it. A log-out only locks it.
export async function forgetAllDevices(fmdId: string): Promise<void> {
  localStorage.removeItem(BUNDLE_PREFIX + fmdId);
  await lockFamily();
}

export function focusDevice(fmdId: string) {
  useFamily.setState({ focus: { fmdId, at: Date.now() } });
}

// --- Latest location ------------------------------------------------------------------------

async function latestV2(fmdId: string, secrets: DeviceSecrets, token: string) {
  const r = await send<{
    items: { clientItemIdHex: string; unixMillis: number; ciphertext64: string }[];
  }>('GET', 'api/v2/data/location', null, token);

  // Newest first; if one will not decrypt, fall back to the one before.
  const items = [...r.items].sort((a, b) => b.unixMillis - a.unixMillis);
  for (const it of items) {
    try {
      const plain = await decryptDataV2(
        fmdId,
        secrets.keysV2!.locationKek,
        'location',
        it.clientItemIdHex,
        it.unixMillis,
        it.ciphertext64
      );
      return JSON.parse(new TextDecoder().decode(plain)) as Location;
    } catch {
      continue;
    }
  }
  return null;
}

async function latestV1(secrets: DeviceSecrets, token: string) {
  const r = await send<string[]>('POST', 'api/v1/locations', { IDT: token, Data: '' });
  for (let i = r.length - 1; i >= 0; i--) {
    try {
      const pkg = JSON.parse(r[i]) as { Data: string };
      const plain = await decryptData(secrets.keysV1!.rsaEncKey, pkg.Data);
      return JSON.parse(plain) as Location;
    } catch {
      continue;
    }
  }
  return null;
}

export async function refreshDevice(fmdId: string): Promise<void> {
  const device = readList().find((d) => d.fmdId === fmdId);
  if (!device) return;
  if (useFamily.getState().status[fmdId]?.needsPassword) return;

  setStatus(fmdId, { loading: true });
  try {
    let secrets = await getSecrets(fmdId);
    if (!secrets) {
      // Brought across from the old plain list with no password: ask, rather than send an
      // empty one, which the server would count towards locking the account.
      if (!device.password) {
        setStatus(fmdId, { needsPassword: true, error: 'Password needed', loading: false });
        return;
      }
      // Locked and opened again: the keys were thrown away, and the password rebuilds them.
      secrets = (await logIn(fmdId, device.password)).secrets;
      await putSecrets(fmdId, secrets);
    }

    const fetchLatest = (token: string) =>
      device.protoVersion === CRYPTO_PROTO_V2
        ? latestV2(fmdId, secrets, token)
        : latestV1(secrets, token);

    let location: Location | null;
    try {
      location = await fetchLatest(secrets.sessionToken);
    } catch (e) {
      if (!(e instanceof AuthError) || e.status !== 401) throw e;
      // The session ran out: log back in once with the stored proof, then try again.
      secrets.sessionToken = await requestToken(fmdId, device.protoVersion, secrets.proof);
      await putSecrets(fmdId, secrets);
      location = await fetchLatest(secrets.sessionToken);
    }

    setStatus(fmdId, { location, fetchedAt: Date.now(), error: null, loading: false });
  } catch (e) {
    if (e instanceof AuthError && e.status === 403) {
      setStatus(fmdId, { needsPassword: true, error: 'Password changed', loading: false });
    } else {
      setStatus(fmdId, {
        error: e instanceof Error ? e.message : 'Could not fetch',
        loading: false,
      });
    }
  }
}

export async function refreshAll(): Promise<void> {
  await Promise.all(readList().map((d) => refreshDevice(d.fmdId)));
}
