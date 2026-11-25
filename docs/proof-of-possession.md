# Device proof-of-possession (Web Crypto) — design and threat analysis

Status: DESIGN ONLY (Nov 24, 2026). Not implemented this round. The bearer
token flow remains in production; nothing here is claimed live.

## Design
1. At "Trust This Browser As Desktop" time, the browser generates a
   non-exportable ECDSA P-256 keypair via WebCrypto
   (`generateKey({name:'ECDSA', namedCurve:'P-256'}, false, ['sign','verify'])`)
   and stores the CryptoKey in IndexedDB. The public key (JWK) is sent to the
   Edge Function during `trust` and stored on the device row
   (`shellagram.devices.pop_key`).
2. `status` becomes two-step for trusted devices: the function returns a
   random 32-byte challenge with a 60-second expiry (stored hashed in a
   `shellagram.challenges` table, single-use); the browser signs
   `challenge || action || tokenHash` and returns the signature; the function
   verifies it against the stored public key before returning session state.
3. Login rotation re-registers the public key only during the fresh
   (10-minute, Telegram-verified) window, so a stolen token alone cannot
   swap in an attacker's key.
4. Revocation is unchanged (lock-desktop / forget-desktop / lock-all delete
   or deactivate the row including its public key).

## What it would and would not fix — stated plainly
- WOULD fix: passive token theft. A token copied out of localStorage (e.g.
  by a same-origin script that only *reads* storage, a backup, or a log)
  becomes useless without the non-exportable key, which never leaves the
  browser's crypto store.
- WOULD NOT fix: an active same-origin attacker. Any script running on
  Shellagram's own origin can *call* WebCrypto with the stored key handle
  and sign whatever it wants while the victim's browser is open —
  non-exportable prevents extraction, not use. Shared-origin risk is only
  truly removed by a dedicated origin (docs/dedicated-domain.md).
- Costs/complexity: IndexedDB key persistence quirks across browsers,
  challenge round-trip on every poll (or signed timestamps with a short
  window instead), recovery flow when IndexedDB is cleared (re-pairing),
  and a second DB table + RPC surface to test. Shipping it half-tested
  would weaken, not strengthen, the current well-tested bearer flow —
  hence design-only until it can be implemented completely with CI tests
  for signature verification, challenge single-use/expiry, and key-swap
  rules.
