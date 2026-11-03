// Run: node --experimental-strip-types --test test/family.test.ts
// Writes test/family-vectors.json, which the Android app's unit test also opens.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { writeFileSync, readFileSync, existsSync } from 'node:fs';
import {
  deriveIdentityKek,
  generateIdentity,
  openIdentity,
  seal,
  open,
} from '../src/lib/familycrypto.ts';

const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64');
const unb64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64'));

const masterKey = async (bytes: Uint8Array) =>
  crypto.subtle.importKey('raw', bytes, 'HKDF', false, ['deriveBits', 'deriveKey']);

test('identity round trip, and a wrong key or user cannot open it', async () => {
  const master = new Uint8Array(32).fill(9);
  const kek = await deriveIdentityKek('alice', await masterKey(master));
  const id = await generateIdentity('alice', kek);
  assert.equal(id.publicRaw.length, 65);
  const again = await openIdentity('alice', kek, id.encPrivate);
  assert.deepEqual(again.publicRaw, id.publicRaw);

  const otherKek = await deriveIdentityKek('alice', await masterKey(new Uint8Array(32).fill(8)));
  await assert.rejects(openIdentity('alice', otherKek, id.encPrivate));
  await assert.rejects(openIdentity('bob', kek, id.encPrivate));
});

test('a place sealed for bob opens for bob only, and only as from alice', async () => {
  const kek = (n: number) =>
    masterKey(new Uint8Array(32).fill(n)).then((m) => deriveIdentityKek('x', m));
  const alice = await generateIdentity('alice', await kek(1));
  const bob = await generateIdentity('bob', await kek(2));
  const carol = await generateIdentity('carol', await kek(3));
  const place = new TextEncoder().encode(
    JSON.stringify({ lat: 1.5, lon: 2.5, date: 1700000000000 })
  );
  const when = 1700000000123;

  const s = await seal('alice', alice.privateKey, 'bob', bob.publicRaw, when, place);
  assert.deepEqual(await open('bob', bob.privateKey, 'alice', alice.publicRaw, when, s), place);

  // Not carol, not as from carol, not at another time, not for another name, not altered.
  await assert.rejects(open('carol', carol.privateKey, 'alice', alice.publicRaw, when, s));
  await assert.rejects(open('bob', bob.privateKey, 'carol', carol.publicRaw, when, s));
  await assert.rejects(open('bob', bob.privateKey, 'alice', alice.publicRaw, when + 1, s));
  await assert.rejects(open('bob', bob.privateKey, 'alicia', alice.publicRaw, when, s));
  const bent = s.slice();
  bent[bent.length - 1] ^= 1;
  await assert.rejects(open('bob', bob.privateKey, 'alice', alice.publicRaw, when, bent));

  // Two seals of the same place differ (fresh ephemeral key and iv every time).
  const s2 = await seal('alice', alice.privateKey, 'bob', bob.publicRaw, when, place);
  assert.notDeepEqual(s, s2);
});

test('vectors for the Android app', async () => {
  const path = new URL('./family-vectors.json', import.meta.url);
  if (existsSync(path) && !process.env.REGEN_VECTORS) {
    // Keep the committed vectors stable; they must still open.
    const v = JSON.parse(readFileSync(path, 'utf8'));
    const kek = await deriveIdentityKek(v.username, await masterKey(unb64(v.masterKey64)));
    const bob = await openIdentity(v.username, kek, unb64(v.encPrivate64));
    assert.equal(b64(bob.publicRaw), v.publicKey64);
    const plain = await open(
      v.username,
      bob.privateKey,
      v.owner,
      unb64(v.ownerPublic64),
      v.unixMillis,
      unb64(v.sealed64)
    );
    assert.equal(new TextDecoder().decode(plain), v.plaintext);
    return;
  }
  const master = crypto.getRandomValues(new Uint8Array(32));
  const kekBob = await deriveIdentityKek('bob', await masterKey(master));
  const bob = await generateIdentity('bob', kekBob);
  const alice = await generateIdentity(
    'alice',
    await deriveIdentityKek('alice', await masterKey(new Uint8Array(32).fill(5)))
  );
  const plaintext = JSON.stringify({
    provider: 'gps',
    lat: 12.5,
    lon: -45.25,
    accuracy: 8,
    bat: 71,
    date: 1700000000000,
  });
  const unixMillis = 1700000000123;
  const sealed = await seal(
    'alice',
    alice.privateKey,
    'bob',
    bob.publicRaw,
    unixMillis,
    new TextEncoder().encode(plaintext)
  );
  writeFileSync(
    path,
    JSON.stringify(
      {
        note: 'Made by web/src/lib/familycrypto.ts. bob is the viewer; alice sealed this place for him.',
        username: 'bob',
        masterKey64: b64(master),
        encPrivate64: b64(bob.encPrivate),
        publicKey64: b64(bob.publicRaw),
        owner: 'alice',
        ownerPublic64: b64(alice.publicRaw),
        unixMillis,
        sealed64: b64(sealed),
        plaintext,
      },
      null,
      2
    ) + '\n'
  );
});

// The other direction: a place sealed by the Android app's FamilyCrypto.kt (its unit test writes
// this file) must open here byte for byte.
test('opens what the Android app sealed', async () => {
  const v = JSON.parse(
    readFileSync(new URL('./family-vectors-kotlin.json', import.meta.url), 'utf8')
  );
  const kek = await deriveIdentityKek(v.username, await masterKey(unb64(v.masterKey64)));
  const me = await openIdentity(v.username, kek, unb64(v.encPrivate64));
  assert.equal(b64(me.publicRaw), v.publicKey64);
  const plain = await open(
    v.username,
    me.privateKey,
    v.owner,
    unb64(v.ownerPublic64),
    v.unixMillis,
    unb64(v.sealed64)
  );
  assert.equal(new TextDecoder().decode(plain), v.plaintext);
  // And not as from anyone else, nor at another time.
  await assert.rejects(
    open(v.username, me.privateKey, v.owner, unb64(v.ownerPublic64), v.unixMillis + 1, unb64(v.sealed64))
  );
});
