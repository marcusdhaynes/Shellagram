# Shellagram

Private single-owner Telegram authentication. Sign in from your phone, and the already paired desktop browser is authorized in the same database transaction. It authenticates Shellagram itself, not Telegram Web, your operating system, or other websites. No Telegram session or login code is transferred.

## Setup

1. Import this repository into Vercel (Other framework, Node 22, public output directory). GitHub Actions runs tests; GitHub Pages alone cannot host the backend.
2. Create a dedicated Supabase project and run db/setup.sql in SQL Editor. Run db/verify.sql for transactional checks. Use the project's URL and server-only secret API key (sb_secret_...). Ensure public is an exposed Data API schema.
3. Create your bot in official @BotFather and configure Login Widget settings. Obtain the OIDC Client ID and Client Secret; retain RS256. Register your HTTPS app origin and the exact redirect URI at /api/callback.
4. Obtain your own numeric Telegram user ID from a trusted source, for example your own bot's getUpdates response after you message it. Never disclose a login code or Telegram password.
5. Configure Vercel production environment variables from .env.example. APP_ORIGIN is the exact HTTPS origin without trailing slash. TELEGRAM_OWNER_ID is your numeric ID, TELEGRAM_CLIENT_ID and TELEGRAM_CLIENT_SECRET are the OIDC credentials, SUPABASE_URL and SUPABASE_SECRET_KEY are your dedicated project settings. FLOW_KEY is 32 random bytes encoded in 64 hex characters; generate locally with node -e "console.log(require('crypto').randomBytes(32).toString('hex'))". Never commit these values. Redeploy.

## Acceptance test

- Sign in on your desktop once and select Trust This Browser As Desktop. Confirm only on a private computer.
- Sign out here and leave the desktop page open.
- Open the same production URL on your phone, preferably using cellular data. Sign in with Telegram.
- Both are authorized immediately at the server. The desktop UI refreshes on a 3-second visible polling interval under normal connectivity (hidden tabs may be throttled); closed or sleeping browsers refresh upon reopening if the authorization is still valid.
- Test Lock Home Desktop, Forget Home Desktop, Lock All Devices, and rejection of another Telegram account.
- Sessions last 12 hours and pairing lasts 90 days (renewed by direct desktop login). Use your operating system lock to protect physical access to the trusted browser.

## Checks

Run npm ci --ignore-scripts, npm run check, npm test, npm start. The local HTTP UI preview is not a live Telegram login. Automated tests use mocked provider/database responses; the SQL checks exercise real database transitions in CI. Real provider and physical-device acceptance tests remain necessary.

All secrets stay on the server. RLS and explicit grants deny public database RPC access. Every future protected API must check active server-side authorization. Configure rate limiting and monitor serverless usage from polling. No runtime package dependencies.

Official documentation: https://core.telegram.org/bots/telegram-login and https://supabase.com/docs/guides/getting-started/api-keys
