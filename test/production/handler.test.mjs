import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
// Tests run against the ACTUAL production Edge Function handler (handler.mjs,
// bound to Deno.serve by index.ts) with Telegram and PostgREST mocked at the
// fetch boundary. Database transition semantics are simplified mirrors of
// db/setup.sql; the SQL itself is tested for real in db/verify.sql (CI
// database job + rollback runs against the live project).
import { createHandler, ORIGIN } from '../../supabase/functions/shellagram-auth/handler.mjs';
import { hash, unseal, challenge, random } from '../../supabase/functions/shellagram-auth/security.mjs';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwks = { keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'k1', use: 'sig', alg: 'RS256' }] };
const ENV = { SHELLAGRAM_TELEGRAM_CLIENT_ID: '123456789', SHELLAGRAM_TELEGRAM_CLIENT_SECRET: 'test-secret', SHELLAGRAM_TELEGRAM_OWNER_ID: '5678', SUPABASE_URL: 'https://db.example', SUPABASE_SERVICE_ROLE_KEY: 'test-db-key' };
const flowKey = hash('shellagram-flow-v1:' + ENV.SHELLAGRAM_TELEGRAM_CLIENT_SECRET);
const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
function jwt(claims) {
  const now = Math.floor(Date.now() / 1000);
  const p = { iss: 'https://oauth.telegram.org', aud: ENV.SHELLAGRAM_TELEGRAM_CLIENT_ID, sub: '4242424242424242', id: 5678, iat: now, exp: now + 3600, ...claims };
  const raw = enc({ alg: 'RS256', kid: 'k1' }) + '.' + enc(p);
  return raw + '.' + sign('RSA-SHA256', Buffer.from(raw), privateKey).toString('base64url');
}

function fixture({ claims = {}, telegramFails = false } = {}) {
  const devices = new Map(); // tokenHash -> {trusted, signedIn, fresh}
  const rateCounts = new Map(); const usedFlows = new Set(); const calls = [];
  const fetcher = async (url, opts = {}) => {
    const u = String(url);
    if (u.endsWith('/.well-known/jwks.json')) return Response.json(jwks);
    if (u === 'https://oauth.telegram.org/token') { if (telegramFails) return new Response('no', { status: 400 }); return Response.json({ id_token: jwt(typeof claims === 'function' ? claims() : claims) }); }
    const body = JSON.parse(opts.body);
    if (u.endsWith('/rpc/shellagram_rate_check')) { const n = (rateCounts.get(body.p_key) || 0) + 1; rateCounts.set(body.p_key, n); return Response.json(n > body.p_limit ? { allowed: false, retryAfter: 42 } : { allowed: true, retryAfter: 0 }); }
    if (u.endsWith('/rpc/shellagram_use_flow')) { if (usedFlows.has(body.p_hash)) return Response.json(false); usedFlows.add(body.p_hash); return Response.json(true); }
    if (u.endsWith('/rpc/shellagram_transition')) {
      calls.push(body.p_action);
      const { p_action: action, p_hash: h, p_new: nw } = body;
      let d = devices.get(h);
      const status = () => { const cur = devices.get(action === 'login' ? nw : h); const desk = [...devices.values()].find((x) => x.trusted); return { signedIn: !!cur?.signedIn, trusted: !!cur?.trusted, fresh: !!cur?.signedIn && !!cur?.fresh, expiresAt: cur?.signedIn ? new Date(Date.now() + 3600e3).toISOString() : null, desktop: cur?.signedIn ? { paired: !!desk, signedIn: !!desk?.signedIn, lastSeen: null, trustExpires: null } : null }; };
      if (action === 'login') { const trusted = !!d?.trusted; devices.delete(h); devices.set(nw, { trusted, signedIn: true, fresh: true }); for (const [k, v] of devices) if (k !== nw && v.trusted) { v.signedIn = true; v.fresh = false; } return Response.json(status()); }
      if (action === 'trust') { if (!d?.signedIn || !d?.fresh) return Response.json({ error: 'Fresh Telegram login required' }); for (const [k, v] of devices) if (k !== h && v.trusted) devices.delete(k); d.trusted = true; return Response.json(status()); }
      if (action === 'logout') { if (d?.trusted) { d.signedIn = false; d.fresh = false; } else devices.delete(h); return Response.json(status()); }
      if (['lock-desktop', 'forget-desktop', 'lock-all'].includes(action)) { if (!d?.signedIn) return Response.json({ error: 'Sign in first' }); for (const [k, v] of devices) { if ((action === 'forget-desktop' && v.trusted) || (action === 'lock-all' && !v.trusted)) devices.delete(k); else if (v.trusted) { v.signedIn = false; v.fresh = false; } } return Response.json(status()); }
      return Response.json(status());
    }
    throw Error('Unexpected fetch ' + u);
  };
  const handler = createHandler({ getEnv: (k) => ENV[k], fetcher });
  let ipSeq = 0;
  async function call(body, { ip, method = 'POST', origin = ORIGIN, type = 'application/json', raw } = {}) {
    const headers = { Origin: origin, 'Content-Type': type, 'cf-connecting-ip': ip || '203.0.113.' + (++ipSeq) };
    const req = new Request('https://db.example/functions/v1/shellagram-auth', { method, headers, body: method === 'POST' ? (raw ?? JSON.stringify(body)) : undefined });
    return handler(req);
  }
  async function start(ip) { const r = await call({ action: 'start' }, { ip }); assert.equal(r.status, 200); return r.json(); }
  return { call, start, devices, calls, usedFlows };
}

test('missing configuration fails closed with 503', async () => {
  const h = createHandler({ getEnv: () => undefined, fetcher: async () => { throw Error('must not fetch'); } });
  const r = await h(new Request('https://x.example/fn', { method: 'POST', headers: { Origin: ORIGIN, 'Content-Type': 'application/json' }, body: '{"action":"status"}' }));
  assert.equal(r.status, 503); assert.match((await r.json()).error, /awaiting Telegram configuration/);
});
test('wrong origin is rejected before anything else', async () => {
  const f = fixture(); const r = await f.call({ action: 'status' }, { origin: 'https://evil.example' });
  assert.equal(r.status, 403);
});
test('method, content-type and size guards', async () => {
  const f = fixture();
  assert.equal((await f.call(null, { method: 'GET' })).status, 405);
  assert.equal((await f.call({ action: 'status' }, { type: 'text/plain' })).status, 415);
  assert.equal((await f.call(null, { raw: 'x'.repeat(9000) })).status, 413);
  assert.equal((await f.call({ action: 'nope' })).status, 404);
});
test('start issues a sealed flow with state, PKCE S256 and a nonce', async () => {
  const f = fixture(); const s = await f.start();
  const u = new URL(s.url); const flow = unseal(s.flow, flowKey);
  assert.equal(u.origin + u.pathname, 'https://oauth.telegram.org/auth');
  assert.equal(u.searchParams.get('state'), s.state);
  assert.equal(u.searchParams.get('scope'), 'openid profile');
  assert.equal(u.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(u.searchParams.get('code_challenge'), challenge(flow.verifier));
  assert.equal(u.searchParams.get('nonce'), flow.nonce);
});
test('finish verifies the owner id claim and rotates the device credential', async () => {
  const f = fixture();
  const s = await f.start();
  const r = await f.call({ action: 'finish', code: 'c', state: s.state, flow: s.flow });
  assert.equal(r.status, 200);
  const body = await r.json();
  assert.equal(body.signedIn, true); assert.ok(body.token);
  const st = await (await f.call({ action: 'status', token: body.token })).json();
  assert.equal(st.signedIn, true);
});
test('finish rejects wrong owner, bad state, and telegram failure', async () => {
  const wrong = createHandler({ getEnv: (k) => ENV[k], fetcher: async (u) => String(u).endsWith('/token') ? Response.json({ id_token: jwt({ id: 9999 }) }) : String(u).includes('jwks') ? Response.json(jwks) : Response.json({ allowed: true, retryAfter: 0 }) });
  const s = await fixture().start();
  const r1 = await wrong(new Request('https://x.example/fn', { method: 'POST', headers: { Origin: ORIGIN, 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'finish', code: 'c', state: s.state, flow: s.flow }) }));
  assert.equal(r1.status, 401);
  const f = fixture(); const s2 = await f.start();
  assert.equal((await f.call({ action: 'finish', code: 'c', state: 'wrong-state', flow: s2.flow })).status, 401);
  const f2 = fixture({ telegramFails: true }); const s3 = await f2.start();
  assert.equal((await f2.call({ action: 'finish', code: 'c', state: s3.state, flow: s3.flow })).status, 401);
});
test('nonce echoed by Telegram must match the sealed flow nonce', async () => {
  const f = fixture();
  const s = await f.start(); const flow = unseal(s.flow, flowKey);
  // Default mock token carries no nonce -> conditional policy accepts.
  assert.equal((await f.call({ action: 'finish', code: 'c', state: s.state, flow: s.flow })).status, 200);
  const f2 = fixture({ claims: { nonce: random() } });
  const s2 = await f2.start();
  assert.equal((await f2.call({ action: 'finish', code: 'c', state: s2.state, flow: s2.flow })).status, 401);
  const f3 = fixture({ claims: () => ({ nonce: unseal(lastFlow.value, flowKey).nonce }) });
  const s3 = await f3.start(); lastFlow.value = s3.flow;
  assert.equal((await f3.call({ action: 'finish', code: 'c', state: s3.state, flow: s3.flow })).status, 200);
  assert.ok(flow.nonce);
});
const lastFlow = { value: null };
test('a completed flow cannot be replayed', async () => {
  const f = fixture(); const s = await f.start();
  assert.equal((await f.call({ action: 'finish', code: 'c', state: s.state, flow: s.flow })).status, 200);
  assert.equal((await f.call({ action: 'finish', code: 'c', state: s.state, flow: s.flow })).status, 401);
});
test('paired desktop unlocks on mobile login; unregistered browser does not', async () => {
  const f = fixture();
  const login = async () => { const s = await f.start(); const r = await f.call({ action: 'finish', code: 'c', state: s.state, flow: s.flow }); return (await r.json()).token; };
  const desktop = await login();
  await f.call({ action: 'trust', token: desktop });
  await f.call({ action: 'logout', token: desktop });
  assert.equal((await (await f.call({ action: 'status', token: desktop })).json()).signedIn, false);
  const mobile = await login();
  assert.equal((await (await f.call({ action: 'status', token: desktop })).json()).signedIn, true);
  assert.equal((await (await f.call({ action: 'status', token: mobile })).json()).signedIn, true);
  assert.equal((await (await f.call({ action: 'status', token: random() })).json()).signedIn, false);
  await f.call({ action: 'lock-desktop', token: mobile });
  assert.equal((await (await f.call({ action: 'status', token: desktop })).json()).signedIn, false);
});
test('rate limit: finish is throttled per IP with 429 + Retry-After', async () => {
  const f = fixture(); const ip = '198.51.100.7';
  for (let i = 0; i < 5; i++) { const s = await f.start(); assert.notEqual((await f.call({ action: 'finish', code: 'c', state: 'bad', flow: s.flow }, { ip })).status, 429); }
  const s = await f.start(); const r = await f.call({ action: 'finish', code: 'c', state: s.state, flow: s.flow }, { ip });
  assert.equal(r.status, 429); assert.equal(r.headers.get('Retry-After'), '42');
});
test('rate limit: start is throttled per IP', async () => {
  const f = fixture(); const ip = '198.51.100.9';
  for (let i = 0; i < 10; i++) assert.equal((await f.call({ action: 'start' }, { ip })).status, 200);
  assert.equal((await f.call({ action: 'start' }, { ip })).status, 429);
});
test('status without a token returns the blank state, never an error', async () => {
  const f = fixture(); const r = await f.call({ action: 'status' });
  assert.equal(r.status, 200); assert.deepEqual(await r.json(), { signedIn: false, trusted: false, fresh: false, expiresAt: null, desktop: null });
});
