# Shellagram

GitHub Pages frontend + isolated Supabase schema and Edge Function. No Vercel. Shellagram authorizes only its own sessions, not Telegram Web or unrelated websites.

## Deployment

Set GitHub Pages source to GitHub Actions in Settings > Pages. The Pages workflow checks the source and deploys public/. The live backend is shellagram-auth in the existing Supabase project. The shellagram.devices table is private; public.shellagram_transition is executable only by service_role. The database migration and rollback-only checks are in db/. The Edge Function source is in supabase/functions/shellagram-auth/.

BotFather: create a bot, open Login Widget, keep RS256, add https://marcusdhaynes.github.io and https://marcusdhaynes.github.io/Shellagram/ to Allowed URLs. Configure SHELLAGRAM_TELEGRAM_CLIENT_ID, SHELLAGRAM_TELEGRAM_CLIENT_SECRET, SHELLAGRAM_TELEGRAM_OWNER_ID in Supabase Edge Function Secrets. No bot token or Telegram password is required at runtime. The owner ID is the numeric Telegram user ID, not a username or bot ID.

Open https://marcusdhaynes.github.io/Shellagram/ on desktop, sign in with Telegram, select Trust This Browser As Desktop, then Sign Out Here. On mobile, open the same URL and sign in with Telegram. Both sessions are authorized atomically; the desktop normally refreshes in up to three seconds if visible and online. Hidden or sleeping tabs update when reopened subject to the 12-hour session limit. Device pairing expires after 90 days.

## Security

Telegram OAuth authorization code + PKCE, encrypted state, signature/issuer/audience/time/owner checks, random hashed device credentials, restricted RPC and RLS, no provider access token persisted. GitHub Pages is static; the edge function performs all privileged operations. This frontend stores the browser-specific opaque Shellagram token in localStorage for cross-browser compatibility. Other GitHub Pages apps under the same github.io hostname share the browser origin and could access it. Use a dedicated Shellagram HTTPS domain for strong frontend origin isolation before relying on it for sensitive data; changing origin requires updating BotFather and the Edge Function. The shared Supabase service role is privileged across the project, not a separate database security boundary. Use the OS screen lock and only trust a private desktop.

The legacy Node handler and tests remain as a local simulation of the original same-origin design, not a production deployment. SQL checks verify the actual database logic; real Telegram and device tests are still required.
