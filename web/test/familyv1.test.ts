// Run (needs node_modules): node --experimental-strip-types --test test/familyv1.test.ts
// Opens the v1 identity that the Overland bridge's Go code wrapped (overland/family_test.go).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { openIdentity } from '../src/lib/familycrypto.ts';
import { deriveIdentityKekV1 } from '../src/lib/familyv1.ts';

const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');
const unb64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));

test('a v1 account identity made by the bridge opens here with the password only', async () => {
  const v = JSON.parse(readFileSync(new URL('./family-vectors-v1.json', import.meta.url), 'utf8'));
  const id = await openIdentity(
    v.username,
    await deriveIdentityKekV1(v.username, v.password),
    unb64(v.encPrivate64)
  );
  assert.equal(b64(id.publicRaw), v.publicKey64);
  await assert.rejects(
    openIdentity(v.username, await deriveIdentityKekV1(v.username, v.password + 'x'), unb64(v.encPrivate64))
  );
});
