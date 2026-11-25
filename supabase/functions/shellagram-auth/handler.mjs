// Shellagram Edge Function handler — production logic, runtime-agnostic so it
// can be unit-tested under Node and executed under Deno (see index.ts).
//
// Hardening (Nov 24, 2026):
// - Telegram OIDC authorization-code + PKCE (S256), state + nonce sealed in an
//   AES-256-GCM flow blob (10-minute expiry). Telegram's docs list `nonce` for
//   the Login library and the profile scope returns the numeric `id` claim
//   (distinct from `sub`); the OIDC discovery document does not list `nonce`
//   or `id` in claims_supported, so nonce is sent on every authorization
//   request and verified whenever Telegram echoes it in the ID token.
// - Server-side rate limiting backed by Postgres (shellagram.rate_limits via
//   the public.shellagram_rate_check RPC): Edge Function instances are
//   stateless, so counters must live in the database. Per-IP and per-token
//   buckets, strictest on finish (login attempts). Exceeding a limit returns
//   429 with Retry-After. A rate-check failure fails closed (503).
// - Replay prevention: after a successful Telegram verification, the flow's
//   state hash is recorded once in shellagram.used_flows via
//   public.shellagram_use_flow; a second finish with the same flow is
//   rejected even if Telegram's one-time code were somehow reusable.
import { random, hash, challenge, seal, unseal, equal, validSecret, verifyIdentity, issuer } from './security.mjs';
import { Buffer } from 'node:buffer';

export const ORIGIN = 'https://marcusdhaynes.github.io';
export const REDIRECT = ORIGIN + '/Shellagram/';
const cors = { 'Access-Control-Allow-Origin': ORIGIN, 'Access-Control-Allow-Methods': 'POST, OPTIONS', 'Access-Control-Allow-Headers': 'content-type', 'Vary': 'Origin', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' };
const blank = { signedIn: false, trusted: false, fresh: false, expiresAt: null, desktop: null };

// action -> [per-IP limit, window seconds, per-token limit or null]
export const RATE_LIMITS = {
  start: [10, 600, null],
  finish: [5, 600, null],
  status: [300, 300, 120],
  trust: [30, 600, 60],
  logout: [30, 600, 60],
  'lock-desktop': [30, 600, 60],
  'forget-desktop': [30, 600, 60],
  'lock-all': [30, 600, 60],
};

export function createHandler({ getEnv, fetcher = fetch } = {}) {
  const envGet = getEnv || ((k) => globalThis.Deno?.env.get(k));
  let keysCache;
  const reply = (data, status = 200, extra = {}) => new Response(JSON.stringify(data), { status, headers: { ...cors, 'Content-Type': 'application/json', ...extra } });

  function config() {
    const clientId = envGet('SHELLAGRAM_TELEGRAM_CLIENT_ID'), secret = envGet('SHELLAGRAM_TELEGRAM_CLIENT_SECRET'), ownerId = envGet('SHELLAGRAM_TELEGRAM_OWNER_ID'), db = envGet('SUPABASE_URL'), key = envGet('SUPABASE_SERVICE_ROLE_KEY');
    if (!/^\d+$/.test(clientId || '') || !secret || !/^\d+$/.test(ownerId || '') || !db || !key) return null;
    return { clientId, secret, ownerId, db, key, flowKey: hash('shellagram-flow-v1:' + secret) };
  }

  async function rpc(c, name, body) {
    const r = await fetcher(c.db + '/rest/v1/rpc/' + name, { method: 'POST', headers: { apikey: c.key, Authorization: 'Bearer ' + c.key, 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(10000), redirect: 'error' });
    if (!r.ok) throw Error('Database unavailable');
    return r.json();
  }
  const transition = (c, action, token, next = null) => rpc(c, 'shellagram_transition', { p_owner: c.ownerId, p_action: action, p_hash: validSecret(token) ? hash(token) : '', p_new: next ? hash(next) : null });

  async function rateCheck(c, bucket, limit, windowSeconds) {
    const out = await rpc(c, 'shellagram_rate_check', { p_key: bucket, p_limit: limit, p_window_seconds: windowSeconds });
    if (!out || typeof out.allowed !== 'boolean') throw Error('Rate limiter unavailable');
    return out;
  }
  async function enforceRate(c, req, action, token) {
    const [ipLimit, windowSeconds, tokenLimit] = RATE_LIMITS[action] || [30, 600, null];
    const ip = (req.headers.get('cf-connecting-ip') || req.headers.get('x-forwarded-for') || 'unknown').split(',')[0].trim().slice(0, 64);
    const ipResult = await rateCheck(c, hash('ip:' + action + ':' + ip), ipLimit, windowSeconds);
    if (!ipResult.allowed) return ipResult;
    if (tokenLimit && validSecret(token)) {
      const tokenResult = await rateCheck(c, hash('token:' + action + ':' + hash(token)), tokenLimit, windowSeconds);
      if (!tokenResult.allowed) return tokenResult;
    }
    return { allowed: true };
  }
  const tooMany = (r) => reply({ error: 'Too many requests. Please wait and try again.' }, 429, { 'Retry-After': String(Math.max(1, Math.ceil(r.retryAfter || 60))) });

  async function verifyTelegram(c, code, verifier, nonce) {
    const r = await fetcher(issuer + '/token', { method: 'POST', headers: { Authorization: 'Basic ' + Buffer.from(c.clientId + ':' + c.secret).toString('base64'), 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, client_id: c.clientId, code_verifier: verifier }), signal: AbortSignal.timeout(10000), redirect: 'error' });
    if (!r.ok) throw Error('Telegram authorization failed');
    const { id_token } = await r.json();
    async function keys(force = false) {
      if (!force && keysCache?.until > Date.now()) return keysCache.data;
      const rr = await fetcher(issuer + '/.well-known/jwks.json', { signal: AbortSignal.timeout(10000), redirect: 'error' });
      if (!rr.ok) throw Error('Keys unavailable');
      const data = await rr.json(); keysCache = { data, until: Date.now() + 300000 }; return data;
    }
    const verify = async () => verifyIdentity(id_token, await keys(), { ...c, nonce });
    try { return await verify(); } catch (e) { if (String(e?.message || e).includes('Nonce')) throw e; return verifyIdentity(id_token, await keys(true), { ...c, nonce }); }
  }

  return async (req) => {
    if (req.headers.get('origin') !== ORIGIN) return reply({ error: 'Origin rejected' }, 403);
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (req.method !== 'POST') return reply({ error: 'Method not allowed' }, 405);
    if (!req.headers.get('content-type')?.startsWith('application/json')) return reply({ error: 'JSON required' }, 415);
    const c = config(); if (!c) return reply({ error: 'Shellagram is awaiting Telegram configuration.' }, 503);
    let b; try { const raw = await req.text(); if (raw.length > 8192) return reply({ error: 'Request too large' }, 413); b = JSON.parse(raw); if (!b || typeof b !== 'object' || Array.isArray(b)) throw Error(); } catch { return reply({ error: 'Invalid request' }, 400); }
    const { action, token } = b;
    try {
      if (action === 'start') {
        const rl = await enforceRate(c, req, 'start', token); if (!rl.allowed) return tooMany(rl);
        const state = random(), verifier = random(), nonce = random(), flow = seal({ state, verifier, nonce, exp: Date.now() + 600000 }, c.flowKey), u = new URL(issuer + '/auth');
        u.search = new URLSearchParams({ client_id: c.clientId, redirect_uri: REDIRECT, response_type: 'code', scope: 'openid profile', state, nonce, code_challenge: challenge(verifier), code_challenge_method: 'S256' });
        return reply({ url: u.toString(), flow, state });
      }
      if (action === 'finish') {
        const rl = await enforceRate(c, req, 'finish', token); if (!rl.allowed) return tooMany(rl);
        let f; try {
          f = unseal(b.flow, c.flowKey);
          if (!equal(f.state, b.state) || typeof b.code !== 'string' || !b.code || b.code.length > 2048) throw Error();
          if (await verifyTelegram(c, b.code, f.verifier, f.nonce) !== c.ownerId) throw Error();
        } catch { return reply({ error: 'Telegram login rejected or expired.' }, 401); }
        // Replay guard: a sealed flow may complete exactly once.
        const fresh_use = await rpc(c, 'shellagram_use_flow', { p_hash: hash(f.state) });
        if (fresh_use !== true) return reply({ error: 'Telegram login rejected or expired.' }, 401);
        const fresh = random(), s = await transition(c, 'login', token, fresh);
        return reply({ ...s, token: fresh });
      }
      if (!['status', 'trust', 'logout', 'lock-desktop', 'forget-desktop', 'lock-all'].includes(action)) return reply({ error: 'Unknown action' }, 404);
      const rl = await enforceRate(c, req, action, token); if (!rl.allowed) return tooMany(rl);
      if (!validSecret(token)) return action === 'status' ? reply(blank) : reply({ error: 'Sign in first' }, 401);
      const s = await transition(c, action, token);
      return reply(s, s.error ? 403 : 200);
    } catch { return reply({ error: 'Authentication service temporarily unavailable.' }, 503); }
  };
}
