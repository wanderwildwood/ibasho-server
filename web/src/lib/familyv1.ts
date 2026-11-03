import { argon2id } from '@noble/hashes/argon2.js';

// The identity wrapping key for an account on the v1 protocol (the Overland bridge's account
// is one). v1 has no master key, so the key comes from the password, the way v1 already wraps
// its RSA private key: Argon2id of "context:familyIdentity" || password, with a salt fixed by
// the username (the first 16 bytes of SHA-256("ibasho_v1_kek_identity" || username)) so every
// log-in finds the same key. overland/family.go makes the same key. Kept apart from
// familycrypto.ts so that file needs no dependencies.

const enc = new TextEncoder();

export async function deriveIdentityKekV1(username: string, password: string): Promise<CryptoKey> {
  const salt = new Uint8Array(
    await crypto.subtle.digest('SHA-256', enc.encode('ibasho_v1_kek_identity' + username))
  ).slice(0, 16);
  const raw = argon2id(enc.encode('context:familyIdentity' + password), salt, {
    t: 1,
    p: 4,
    m: 131072,
    dkLen: 32,
  });
  return crypto.subtle.importKey('raw', raw as Uint8Array<ArrayBuffer>, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
