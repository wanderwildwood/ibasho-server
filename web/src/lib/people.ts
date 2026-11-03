import { ApiError, HTTP, requestV2, type Location } from './api';
import { base64Decode, base64Encode } from './crypto';
import { generateIdentity, open, openIdentity, type Identity } from './familycrypto';
import { useStore } from './store';

// The people who share their last known place with this account. Each phone seals its place
// separately for each person; here it is opened in the browser with this account's own key.
// The server holds only the sealed copies and never sees a coordinate.

const API = 'api/v2';

interface IdentityBody {
  publicKey64: string;
  encPrivateKey64: string;
}

interface FamilyResponse {
  me: { username: string; paused: boolean };
  people: { username: string; publicKey64: string; paused: boolean }[];
}

interface SealedResponse {
  items: { owner: string; unixMillis: number; ciphertext64: string }[];
}

export type PersonState = 'ok' | 'paused' | 'no_key' | 'none' | 'unreadable';

export interface Person {
  name: string;
  state: PersonState;
  location?: Location;
  unixMillis?: number;
}

export interface People {
  paused: boolean;
  people: Person[];
}

export class NeedsLogin extends Error {
  constructor() {
    super('needs login');
    Object.setPrototypeOf(this, NeedsLogin.prototype);
  }
}

let cached: { user: string; identity: Identity } | null = null;

/** This account's identity: opened from the server, or made now if it has none yet. */
async function myIdentity(): Promise<Identity> {
  const { userData } = useStore.getState();
  const kek = userData?.keysV2?.identityKek ?? userData?.keysV1?.identityKek;
  if (!userData || !kek) throw new NeedsLogin();
  if (cached?.user === userData.fmdId) return cached.identity;

  const adopt = async (body: IdentityBody) =>
    openIdentity(userData.fmdId, kek, base64Decode(body.encPrivateKey64));

  let identity: Identity;
  try {
    identity = await adopt(await requestV2<IdentityBody>(HTTP.GET, `${API}/account/identity`));
  } catch (e) {
    if (!(e instanceof ApiError) || e.status !== 404) throw e;
    const made = await generateIdentity(userData.fmdId, kek);
    const body: IdentityBody = {
      publicKey64: base64Encode(made.publicRaw),
      encPrivateKey64: base64Encode(made.encPrivate),
    };
    try {
      await requestV2(HTTP.POST, `${API}/account/identity`, body);
      identity = made;
    } catch (e2) {
      // Another device made one first; the first one wins.
      if (!(e2 instanceof ApiError) || e2.status !== 409) throw e2;
      identity = await adopt(JSON.parse(e2.message) as IdentityBody);
    }
  }
  cached = { user: userData.fmdId, identity };
  return identity;
}

export async function loadPeople(): Promise<People> {
  const { userData } = useStore.getState();
  const me = await myIdentity();
  const [family, sealed] = await Promise.all([
    requestV2<FamilyResponse>(HTTP.GET, `${API}/family`),
    requestV2<SealedResponse>(HTTP.GET, `${API}/family/locations`),
  ]);

  const people: Person[] = [];
  for (const p of family.people) {
    if (p.paused) {
      people.push({ name: p.username, state: 'paused' });
      continue;
    }
    if (!p.publicKey64) {
      people.push({ name: p.username, state: 'no_key' });
      continue;
    }
    const item = sealed.items.find((i) => i.owner === p.username);
    if (!item) {
      people.push({ name: p.username, state: 'none' });
      continue;
    }
    try {
      const plain = await open(
        userData!.fmdId,
        me.privateKey,
        p.username,
        base64Decode(p.publicKey64),
        item.unixMillis,
        base64Decode(item.ciphertext64)
      );
      const location = JSON.parse(new TextDecoder().decode(plain)) as Location;
      if (!Number.isFinite(location.lat) || !Number.isFinite(location.lon)) throw new Error('bad');
      people.push({ name: p.username, state: 'ok', location, unixMillis: item.unixMillis });
    } catch {
      people.push({ name: p.username, state: 'unreadable' });
    }
  }
  return { paused: family.me.paused, people };
}

export async function setPaused(paused: boolean): Promise<void> {
  await requestV2(HTTP.POST, `${API}/family/pause`, { paused });
}
