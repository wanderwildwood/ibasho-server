// Family sharing: the identity key pair and the sealed copies of a last known place.
//
// Whereabouts for Android implements the same scheme (crypto/FamilyCrypto.kt). The two must stay
// byte-for-byte compatible; web/test/family.test.ts reads vectors both ends check.
//
// Identity: a P-256 key pair per account.
//   public     the 65-byte uncompressed point, sent to the server in the clear.
//   private    d (32 bytes) || public (65 bytes), encrypted with AES-256-GCM under a key made
//              from the account's master key, so every login of the account (phone, browser)
//              can open it and the server cannot:
//                kek = HKDF-SHA256(master key, salt empty, info = "ibasho_v1_kek_identity" || SHA256(username))
//                stored = iv(12) || ciphertext || tag(16), AD = "ibasho_v1_identity" || SHA256(username)
//
// Sealed copy of a place, from `owner` to one `viewer`:
//   0x01 || ephemeral public (65) || iv (12) || AES-256-GCM(key, plaintext) (ciphertext || tag)
//   ikm = ECDH(ephemeral private, viewer public) || ECDH(owner private, viewer public)   (32 + 32)
//   key = HKDF-SHA256(ikm, salt empty, info = "ibasho_v1_seal" || 0x00 || owner || 0x00 || viewer)
//   AD  = "ibasho_v1_seal" || SHA256(owner) || SHA256(viewer) || unixMillis (8 bytes, big endian)
// The first ECDH keeps the copy private to the viewer; the second, with the owner's own key,
// makes it something only the owner could have made, so the server cannot forge a place.

const enc = new TextEncoder();

const CTX_KEK_IDENTITY = enc.encode('ibasho_v1_kek_identity');
const CTX_IDENTITY = enc.encode('ibasho_v1_identity');
const CTX_SEAL = enc.encode('ibasho_v1_seal');

const IV_BYTES = 12;
const POINT_BYTES = 65;
const SEAL_VERSION = 1;

type Bytes = Uint8Array<ArrayBuffer>;

export interface Identity {
  /** The 65-byte uncompressed public point. */
  publicRaw: Bytes;
  /** For ECDH only; cannot be exported. */
  privateKey: CryptoKey;
  /** What the server keeps: the private half, encrypted. */
  encPrivate: Bytes;
}

const concat = (...parts: Uint8Array[]): Bytes => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};

const sha256 = async (data: Uint8Array): Promise<Bytes> =>
  new Uint8Array(await crypto.subtle.digest('SHA-256', data as Bytes));

const millisBytes = (millis: number): Bytes => {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(millis), false);
  return out;
};

const hkdf = async (ikm: Uint8Array, info: Uint8Array): Promise<CryptoKey> => {
  const base = await crypto.subtle.importKey('raw', ikm as Bytes, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(), info: info as Bytes },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
};

/** The key that wraps the identity private key, from the master key (an HKDF key). */
export async function deriveIdentityKek(
  username: string,
  masterKey: CryptoKey
): Promise<CryptoKey> {
  const info = concat(CTX_KEK_IDENTITY, await sha256(enc.encode(username)));
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(), info },
    masterKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// PKCS#8 for a P-256 key, with the public point included. WebCrypto will not import a bare
// private scalar, so one is wrapped in this fixed frame.
const PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
  0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02,
  0x01, 0x01, 0x04, 0x20,
]);
const PKCS8_MIDDLE = Uint8Array.from([0xa1, 0x44, 0x03, 0x42, 0x00]);

const importPrivate = (d: Uint8Array, publicRaw: Uint8Array): Promise<CryptoKey> =>
  crypto.subtle.importKey(
    'pkcs8',
    concat(PKCS8_PREFIX, d, PKCS8_MIDDLE, publicRaw),
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits']
  );

export const importPublic = (publicRaw: Uint8Array): Promise<CryptoKey> =>
  crypto.subtle.importKey(
    'raw',
    publicRaw as Bytes,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

/** Makes a new identity for the account and wraps its private half under `kek`. */
export async function generateIdentity(username: string, kek: CryptoKey): Promise<Identity> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveBits',
  ]);
  const publicRaw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  const d = Uint8Array.from(atob(jwk.d!.replace(/-/g, '+').replace(/_/g, '/') + '='), (c) =>
    c.charCodeAt(0)
  );
  // JWK drops leading zeros of nothing here: P-256 d is always exactly 32 bytes in a JWK.
  if (d.length !== 32) throw new Error('unexpected private key size');

  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const ad = concat(CTX_IDENTITY, await sha256(enc.encode(username)));
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: ad },
      kek,
      concat(d, publicRaw)
    )
  );
  return {
    publicRaw,
    privateKey: await importPrivate(d, publicRaw),
    encPrivate: concat(iv, sealed),
  };
}

/** Opens the identity the server holds. Throws if the key is wrong or the data was altered. */
export async function openIdentity(
  username: string,
  kek: CryptoKey,
  encPrivate: Uint8Array
): Promise<Identity> {
  const iv = encPrivate.subarray(0, IV_BYTES) as Bytes;
  const ad = concat(CTX_IDENTITY, await sha256(enc.encode(username)));
  const plain = new Uint8Array(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: ad },
      kek,
      encPrivate.subarray(IV_BYTES) as Bytes
    )
  );
  if (plain.length !== 32 + POINT_BYTES) throw new Error('identity has the wrong size');
  const d = plain.subarray(0, 32);
  const publicRaw = plain.slice(32);
  return {
    publicRaw,
    privateKey: await importPrivate(d, publicRaw),
    encPrivate: concat(encPrivate),
  };
}

const ecdh = async (priv: CryptoKey, pub: CryptoKey): Promise<Bytes> =>
  new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: pub }, priv, 256));

const sealKeyAndAd = async (
  ikm: Uint8Array,
  owner: string,
  viewer: string,
  unixMillis: number
): Promise<[CryptoKey, Bytes]> => {
  const info = concat(
    CTX_SEAL,
    Uint8Array.of(0),
    enc.encode(owner),
    Uint8Array.of(0),
    enc.encode(viewer)
  );
  const ad = concat(
    CTX_SEAL,
    await sha256(enc.encode(owner)),
    await sha256(enc.encode(viewer)),
    millisBytes(unixMillis)
  );
  return [await hkdf(ikm, info), ad];
};

/** Seals `plaintext` from `owner` to `viewer`. */
export async function seal(
  owner: string,
  ownerPrivate: CryptoKey,
  viewer: string,
  viewerPublicRaw: Uint8Array,
  unixMillis: number,
  plaintext: Uint8Array
): Promise<Bytes> {
  const viewerPub = await importPublic(viewerPublicRaw);
  const eph = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveBits',
  ]);
  const ephRaw = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
  const ikm = concat(await ecdh(eph.privateKey, viewerPub), await ecdh(ownerPrivate, viewerPub));
  const [key, ad] = await sealKeyAndAd(ikm, owner, viewer, unixMillis);
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const body = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: ad },
      key,
      plaintext as Bytes
    )
  );
  return concat(Uint8Array.of(SEAL_VERSION), ephRaw, iv, body);
}

/** Opens a copy `owner` sealed for `viewer`. Throws if it is not from that owner for that viewer. */
export async function open(
  viewer: string,
  viewerPrivate: CryptoKey,
  owner: string,
  ownerPublicRaw: Uint8Array,
  unixMillis: number,
  sealed: Uint8Array
): Promise<Bytes> {
  if (sealed.length < 1 + POINT_BYTES + IV_BYTES + 16 || sealed[0] !== SEAL_VERSION) {
    throw new Error('not a sealed place');
  }
  const ephRaw = sealed.subarray(1, 1 + POINT_BYTES);
  const iv = sealed.subarray(1 + POINT_BYTES, 1 + POINT_BYTES + IV_BYTES) as Bytes;
  const body = sealed.subarray(1 + POINT_BYTES + IV_BYTES);
  const ikm = concat(
    await ecdh(viewerPrivate, await importPublic(ephRaw)),
    await ecdh(viewerPrivate, await importPublic(ownerPublicRaw))
  );
  const [key, ad] = await sealKeyAndAd(ikm, owner, viewer, unixMillis);
  return new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: ad }, key, body as Bytes)
  );
}
