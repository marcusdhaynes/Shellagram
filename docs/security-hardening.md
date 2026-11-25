# Security hardening — Nov 24, 2026 round

## Rate limiting (implemented, live in DB; function code in repo)
Edge Function instances are stateless, so counters live in Postgres:
`shellagram.rate_limits` + `public.shellagram_rate_check(text,int,int)`
(fixed-window, advisory-lock atomic increment, per-bucket cleanup of old
windows, RLS deny-all, service_role only). The handler checks before
dispatch: per-IP buckets for every action and per-token buckets for
authenticated actions — start 10/10min, finish 5/10min (strictest: login
attempts), status 300/5min per IP + 120/5min per token (polling-friendly),
trust/logout/lock actions 30/10min per IP + 60/10min per token. Limit hits
return HTTP 429 with `Retry-After`. A rate-check outage fails closed (503),
consistent with the rest of the function. Residual: limits are per-IP, so a
distributed attack is blunted, not stopped; Supabase platform limits apply
in front.

## Replay prevention (strengthened)
Before: state + PKCE + sealed 10-minute flow + Telegram's one-time code.
Added: (a) OIDC `nonce` generated per flow, sent on the authorization
request, verified when echoed (see docs/telegram-oidc.md); (b) a server-side
single-use flow store — `shellagram.used_flows` +
`public.shellagram_use_flow(text)` records the hash of a flow's state after
successful Telegram verification, and any second `finish` with the same
flow is rejected. Flow expiry stays at 10 minutes: it must comfortably
cover a phone app-switch to Telegram and back; the single-use store, not a
shorter clock, is what closes the replay window.

## Sessions and device credentials (verified, unchanged where sound)
- Login rotates the device credential every time (old hash deleted, new
  random 32-byte token issued; only SHA-256 hashes are stored).
- Active window 12h; trusted pairing 90 days; `trust` requires a fresh
  (10-minute) Telegram-verified window; one trusted desktop per owner is
  enforced by a partial unique index + advisory lock.
- Revocation: logout (this device), lock-desktop, forget-desktop, lock-all
  — all in `public.shellagram_transition`, all covered by db/verify.sql.
- Tradeoff kept deliberately: the 12-hour window is what lets a desktop
  unlock when it wakes/reconnects after a phone sign-in; shortening it
  would break the core use case, and revocation covers the risk instead.

## Removed
The legacy Node handler (`api/`, `lib/`, `local.mjs`) simulated an abandoned
same-origin design, called a non-existent `sg_transition` RPC, and was the
only thing the old tests exercised. It is deleted; the production Deno Edge
Function now has its own test suite (test/production/) wired into CI, plus
a Deno runtime smoke test and the Postgres CI job running db/setup.sql +
db/verify.sql.
