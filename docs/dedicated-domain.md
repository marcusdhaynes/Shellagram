# Dedicated domain for Shellagram — analysis and recommendation

## Why
`marcusdhaynes.github.io` is a single browser origin shared by every GitHub
Pages site Marcus hosts. Path separation (`/Shellagram/` vs. other apps) is
not a security boundary: any script running on any of those apps can read
Shellagram's `localStorage` device token (`shellagram.device.v1`). A
dedicated hostname gives Shellagram its own origin and removes that entire
class of exposure. It does not fix XSS inside Shellagram itself, and it does
not make the bearer token non-stealable by a script already running on
Shellagram's own origin (see docs/proof-of-possession.md).

## Options (no new hosting, no Vercel)

### Option A — Subdomain of an existing domain (RECOMMENDED, $0)
Use `shellagram.somniel.com` (somniel.com is already Marcus's, on DreamHost):
1. DreamHost DNS: add a CNAME record `shellagram` -> `marcusdhaynes.github.io`.
2. GitHub repo Settings > Pages > Custom domain: `shellagram.somniel.com`,
   wait for DNS check, then enable "Enforce HTTPS" (GitHub provisions a free
   Let's Encrypt certificate automatically).
3. Add a `CNAME` file containing `shellagram.somniel.com` to `public/` in the
   repo so the setting survives deploys.
4. Update BotFather > Login Widget > Allowed URLs: replace the github.io
   origin/redirect with `https://shellagram.somniel.com` and
   `https://shellagram.somniel.com/` (keep the old ones listed until cutover
   is verified, then remove them).
5. Update the Edge Function: `ORIGIN`/`REDIRECT` constants in
   `supabase/functions/shellagram-auth/handler.mjs`, the frontend endpoint
   stays the same but the page origin changes automatically, then redeploy
   the function.
6. Re-register the trusted desktop once on the new origin (localStorage does
   not migrate across origins — expected, one-time).

Cost: $0. New origin: `https://shellagram.somniel.com` — fully separate
storage, cookies, and CSP scope from every other app.

### Option B — New dedicated domain (~$10–15/year)
Same steps with a domain used only for Shellagram (e.g. shellagram.app if
available). Marginally cleaner separation from the Somniel brand, but adds
renewal cost and another domain to manage, with no security advantage over
Option A — a subdomain is already a distinct origin (and a distinct site for
cookie purposes when set up as its own host).

### Option C — Stay on marcusdhaynes.github.io ($0, not recommended long-term)
Accept that every Pages app Marcus publishes shares an origin with
Shellagram's device token. Mitigations already in place (hashed server-side
storage, 12-hour active window, 90-day pairing, remote lock/forget,
lock-all) limit blast radius but cannot prevent token theft by a compromised
or malicious same-origin app.

## Recommendation
Option A: `shellagram.somniel.com`. Zero cost, distinct origin, uses only
GitHub Pages + existing DreamHost DNS. No purchase or DNS change has been
made — both require Marcus's go-ahead, and the BotFather/Edge Function
origin updates must ship in the same sitting as the DNS change or logins
break in between.
