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

// The other devices on the map: accounts on this same server whose owners gave you their
// password. Nothing here touches the main login. Each device keeps its own session and keys,
// and a device whose session runs out logs itself back in; it never logs you out.
//
// What is kept, per device:
// - in localStorage, the name to show, the account id and its protocol version;
// - in IndexedDB, its keys (non-extractable CryptoKeys, as upstream stores the main account's),
//   its session token, and the proof the server asks for at log-in. The proof is the
//   password *hash*, never the password, so a stored device cannot be used to read the
//   password back.

const LIST_KEY = 'ibasho-family';
const DB_NAME = 'ibasho-family';
const STORE_NAME = 'devices';
const ONE_WEEK_SECONDS = 7 * 24 * 60 * 60;

export interface FamilyDevice {
  fmdId: string;
  name: string;
  protoVersion: number;
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
  status: Record<string, DeviceStatus>;
  // Set when a device is picked in the list; the map pans to it.
  focus: { fmdId: string; at: number } | null;
}

export const useFamily = create<FamilyState>()(() => ({
  devices: readList(),
  status: {},
  focus: null,
}));

function readList(): FamilyDevice[] {
  try {
    const raw = localStorage.getItem(LIST_KEY);
    return raw ? (JSON.parse(raw) as FamilyDevice[]) : [];
  } catch {
    return [];
  }
}

function writeList(devices: FamilyDevice[]) {
  localStorage.setItem(LIST_KEY, JSON.stringify(devices));
  useFamily.setState({ devices });
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
    const request = indexedDB.open(DB_NAME, 1);
    request.onerror = () => reject(new Error(request.error?.message || 'Failed to open database'));
    request.onsuccess = () => resolve(request.result);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) {
        request.result.createObjectStore(STORE_NAME);
      }
    };
  });
}

async function withStore<T>(
  mode: IDBTransactionMode,
  op: (store: IDBObjectStore) => IDBRequest
): Promise<T> {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const request = op(db.transaction(STORE_NAME, mode).objectStore(STORE_NAME));
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
  if (readList().some((d) => d.fmdId === fmdId)) throw new Error('That device is already here');

  const { protoVersion, secrets } = await logIn(fmdId, password);
  await putSecrets(fmdId, secrets);
  writeList([...readList(), { fmdId, name: name.trim() || fmdId, protoVersion }]);
  await refreshDevice(fmdId);
}

// A device whose password changed gets the new one. The old keys stay until the new
// password has actually logged in, so a mistyped one loses nothing.
export async function reenterPassword(fmdId: string, password: string): Promise<void> {
  const { protoVersion, secrets } = await logIn(fmdId, password);
  await putSecrets(fmdId, secrets);
  writeList(readList().map((d) => (d.fmdId === fmdId ? { ...d, protoVersion } : d)));
  setStatus(fmdId, { needsPassword: false, error: null });
  await refreshDevice(fmdId);
}

export async function removeDevice(fmdId: string): Promise<void> {
  await deleteSecrets(fmdId);
  writeList(readList().filter((d) => d.fmdId !== fmdId));
  useFamily.setState((s) => {
    const status = { ...s.status };
    delete status[fmdId];
    return { status };
  });
}

// On an explicit log-out, forget every device too.
export async function forgetAllDevices(): Promise<void> {
  localStorage.removeItem(LIST_KEY);
  await clearSecrets();
  useFamily.setState({ devices: [], status: {}, focus: null });
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
    const secrets = await getSecrets(fmdId);
    if (!secrets) throw new Error('Keys missing from this browser');

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
