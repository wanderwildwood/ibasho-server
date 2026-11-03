# Family locations: plan

The same document lives in both repos (`ibasho/docs/PLAN-family.md` and
`ibasho-server/docs/PLAN-family.md`). Status: design plus a first slice on branch `family` in
both. Nothing here is released or deployed.

## What it is

A household runs one Whereabouts server. Each phone already uploads its own encrypted
locations there for finding itself. Family locations adds one thing: a person can let chosen
other people on the same server see **where their phone was last**, and nothing more. The
server carries sealed copies it cannot open.

It is not a tracker. There is no trail, no history, no geofence, no alert, and no way to make
someone else's phone report.

## Who is family, and how people join

- Family = the accounts on one server. Registration is already closed behind a registration
  token; handing someone the server address and the token *is* the invitation. There is no
  second invite system.
- One account is one device (as today: one for each phone). A person is shown by the account
  name they registered with.
- Anyone signed in can see the **list of names** on the server and whether each has set up
  sharing. They see a **place** only for people who chose to share with them.

## Who can see whom (opt-in, per person)

- Sharing is **off** on a new or updated phone. The phone's owner turns it on in the Family
  screen and ticks each person they want to share with. Nobody is ticked by default.
- Sharing is one-way: Ada sharing with Tomas does not make Tomas share with Ada.
- Unticking a person, or turning sharing off, removes that person's copy from the server on the
  next upload (turning off removes all of them at once, at the moment it is switched).
- "Pause" on the server is the off switch: while paused, the server refuses new copies and
  holds none. The web page has the same switch, so a person can stop sharing from a computer
  if the phone is lost.
- The choice of whom to share with lives on the phone. The server cannot add a viewer: a copy
  exists only if the owner's phone sealed it to that viewer's key.

## What is kept

- For each (owner, viewer) pair the server keeps **one** sealed copy of the owner's last known
  place, replaced by newer ones. No history beyond that.
- The owner's own location history is unchanged (the server's existing per-account limit).
- Deleting an account removes its key, every copy it made and every copy made for it.

## Encryption

Built on the existing v2 account keys, so every login of an account (phone or browser) can open
what is sealed to it, and the server cannot.

- **Identity key**: one P-256 key pair per account. The public half is stored in the clear. The
  private half (d || public point) is stored encrypted with AES-256-GCM under
  `HKDF-SHA256(master key, info = "ibasho_v1_kek_identity" || SHA256(username))`, with
  AD `"ibasho_v1_identity" || SHA256(username)`. Only someone with the account password (which
  opens the master key) can open it. The first identity posted wins; a second device that
  raced adopts it (HTTP 409 returns the winner).
- **Sealed copy** from owner to viewer:
  `0x01 || ephemeral public (65) || iv (12) || AES-256-GCM(ciphertext || tag)`, key =
  `HKDF-SHA256(ECDH(eph, viewer) || ECDH(owner, viewer), info = "ibasho_v1_seal" 0x00 owner 0x00 viewer)`,
  AD = `"ibasho_v1_seal" || SHA256(owner) || SHA256(viewer) || unixMillis (8 bytes BE)`.
  The ephemeral half makes the copy private to the viewer; the owner's static half proves it
  came from the owner, so the server can neither read nor forge a place, nor move a copy to
  another pair or another time.
- The plaintext is the app's existing location JSON (provider, lat, lon, accuracy, altitude,
  heading, speed, bat, date, time).
- Both ends implement the same bytes: `web/src/lib/familycrypto.ts` and
  `app/.../crypto/FamilyCrypto.kt`, checked against shared test vectors in both directions.

### Trusting the keys

The server hands out the public keys, so a dishonest server could hand over its own key in
place of a family member's. The phone therefore **pins** each person's key the first time it
seals to them, and if the server later shows a different key it stops sealing to that person
and says so on the Family screen ("their key changed"). The person can accept the new key (for
example after that account was deleted and made again) with a deliberate double tap. The old copy, sealed to the old key,
is left on the server: only the real person can open it. A short fingerprint on each row lets
two people compare in person if they want to. The phone pins keys it sees when looking, too, and
shows "their key changed" instead of a place that would open under a swapped key.

The web page does not pin (a browser session is not a lasting place to keep pins); it trusts the
server's list. The phone is the stronger check.

## What the server can and cannot see

Can see: account names; who has set up an identity; each person's pause switch; **which pairs
share** (Ada → Tomas), when each copy was last replaced, and its size; IP addresses and times of
requests, as today.

Cannot see: any coordinate, accuracy, battery, or time of fix inside a copy; any identity
private key; any account password. It cannot create a sharing pair or alter a place without the
viewer's app rejecting it.

## What leaves the phone

Only what already leaves it, plus copies of the same place: on each regular upload, the phone
seals that location once for each person it shares with (about 300 bytes each) and sends them
to its own server over HTTPS. Nothing goes to any third party. Turning sharing off sends one
"pause" request. Opening the Family screen asks the server for the people list and the copies
sealed to this phone, and opens them on the phone.

## Battery and wake behavior on the Kompakt

- **No new alarms, jobs, wake locks or location requests.** Sharing rides on the existing
  regular upload (job 108, default every 60 minutes) and on Locate commands: after the normal
  upload succeeds, the same fix is sealed and sent in one more request.
- **Viewing is pull-only**: the Family screen loads when opened and when pulled down. Nothing
  polls in the background. (The web page refreshes once a minute only while it is visible.)
- **DuraSpeed**: if it stops the app, the regular upload stops and so does sharing; the
  existing "Regular uploads" warning already covers it. On the viewer's side each person shows
  "last shared N ago", so a stale place is visibly stale rather than silently wrong.
- A GPS-only Kompakt indoors often has no fix; then there is nothing new to share and the last
  copy stays, with its age shown.

## The iPhone (Overland) account

The Overland account's locations are encrypted by the shim on the server, which therefore
already sees them in the clear. To share them, the shim would hold that account's identity
key and seal like a phone does. That costs nothing in privacy compared with today, but it is a
server-held secret. Not in the first slice; needs a decision.

## Slices

1. **First slice (built on branch `family`)**
   - Server: identity, people list, pause, sealed copies with an `audience` field that drops
     copies for anyone the owner no longer shares with; migration 6; Go tests.
   - Web: a People page (a viewer: names, last place, age, battery; pause switch), crypto with
     test vectors.
   - App: `FamilyCrypto` (same bytes as the web), the API calls, the sharing step after each
     regular upload, key pinning, and a Family screen under Settings (sharing on/off, tick
     people, see who shares with you, open a place in whatever map app the phone has). Logging
     out of the server forgets the choices and pins.
2. **Next**: Overland sealing in the shim; a small map on the Family screen instead of handing
   off to a map app; "ask for a fresh place" (a push to the other phone, only if that person
   allows it); fingerprints compared by QR.
3. **Not planned**: trails, history, geofences, arrival alerts.

## Open questions

1. Opt-in per person (this plan) or everyone-sees-everyone with one pause switch (the earlier
   server WIP said "everyone registered can be seen")?
2. Is pinning plus a "key changed" warning enough, or should sharing need an in-person
   fingerprint check first?
3. Should the server drop copies older than some age (say 7 days), or keep the last one forever
   with its age shown?
4. Overland: let the shim hold the iPhone account's identity key so that account can share?
