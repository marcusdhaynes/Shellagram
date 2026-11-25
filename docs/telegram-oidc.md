# Telegram OIDC — verified against primary sources (Nov 24, 2026)

Sources:
- Telegram, "Log In With Telegram": https://core.telegram.org/bots/telegram-login
- Telegram OIDC discovery document: https://oauth.telegram.org/.well-known/openid-configuration

## Findings

1. **The numeric user ID is the `id` claim, returned by the `profile` scope — it is NOT `sub`.**
   The docs' scope table states: `openid` returns `sub`, `iss`, `iat`, `exp`;
   `profile` returns `id`, `name`, `preferred_username`, `picture` ("User's basic
   info: user ID, name, username, and profile photo URL"). The example ID token
   in the same page shows `"sub": "1234123412341234123"` (a long opaque string)
   alongside `"id": 987654321` (the numeric Telegram user ID). Shellagram's
   owner check therefore compares `SHELLAGRAM_TELEGRAM_OWNER_ID` against the
   `id` claim, exactly as documented. Substituting `sub` would be wrong.
   Caveat: the discovery document's `claims_supported` list omits `id` (it
   lists aud, preferred_username, phone_number, exp, iat, iss, name, picture,
   sub, ton). The documentation page and its example token are explicit that
   `profile` returns `id`, and Shellagram requests `openid profile`; the first
   real sign-in remains the final confirmation. Verification fails closed if
   `id` is absent or not numeric.

2. **`nonce` is documented for the Telegram Login library, ambiguous for raw OIDC.**
   The Login library's InitOptions document `nonce` as an "Optional.
   Server-generated random string to be included in the resulting `id_token`
   to prevent replay attacks." The manual OIDC authorization example in the
   same document does not list a `nonce` parameter, and the discovery document
   does not list `nonce` in `claims_supported`. Shellagram therefore:
   generates a fresh nonce per flow, seals it with state + PKCE verifier,
   sends it on every authorization request, and verifies it **whenever the
   ID token echoes a nonce claim** (a mismatched echo is rejected; an absent
   claim is tolerated). This is the strongest behavior the documented surface
   supports without risking false rejections if Telegram ignores the
   parameter in the raw OIDC flow.

3. Other confirmations: authorization-code flow with PKCE (S256 listed in
   `code_challenge_methods_supported`); token endpoint auth
   `client_secret_basic`; ID tokens signed RS256 by default (BotFather >
   Login Widget > Advanced changes the algorithm — Shellagram requires
   RS256 and the bot must stay on the default); issuer
   `https://oauth.telegram.org`; JWKS at
   `https://oauth.telegram.org/.well-known/jwks.json`; no UserInfo endpoint.
   Client ID and Client Secret are displayed in @BotFather > Login Widget.
