import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, randomBytes } from 'node:crypto';
// Tests run against the ACTUAL production Edge Function security module.
import { verifyIdentity, issuer, random, seal, unseal, challenge, hash, validSecret } from '../../supabase/functions/shellagram-auth/security.mjs';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwks = { keys: [{ ...publicKey.export({ format: 'jwk' }), kid: 'k', use: 'sig', alg: 'RS256' }] };
const now = 1700000000;
const NONCE = random();
// Per Telegram docs the profile scope returns numeric `id`, distinct from `sub`.
const good = { iss: issuer, aud: '1234', sub: '1234123412341234123', id: 5678, iat: now - 1, exp: now + 3600 };
const c = { clientId: '1234', ownerId: '5678', now };
const enc = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
function jwt(p = good, h = { alg: 'RS256', kid: 'k' }) { const raw = enc(h) + '.' + enc(p); return raw + '.' + sign('RSA-SHA256', Buffer.from(raw), privateKey).toString('base64url'); }

test('valid signed owner ID (numeric id claim, not sub)', () => assert.equal(verifyIdentity(jwt(), jwks, c), '5678'));
test('owner is the id claim: a token whose sub equals the owner but id differs is rejected', () =>
  assert.throws(() => verifyIdentity(jwt({ ...good, sub: '5678', id: 9999 }), jwks, c)));
test('string form of numeric id is accepted', () => assert.equal(verifyIdentity(jwt({ ...good, id: '5678' }), jwks, c), '5678'));
for (const [name, change] of Object.entries({
  'wrong owner': { id: 999 }, 'wrong audience': { aud: '321' }, 'wrong issuer': { iss: 'https://example.com' },
  'expired': { exp: now }, 'future issued': { iat: now + 100 }, 'stale issuance': { iat: now - 601 },
  'missing subject': { sub: '' }, 'future not before': { nbf: now + 100 }, 'unsafe numeric ID': { id: 9007199254740992 },
})) test('reject ' + name, () => assert.throws(() => verifyIdentity(jwt({ ...good, ...change }), jwks, c)));
test('reject unsigned or wrong algorithm', () => assert.throws(() => verifyIdentity(jwt(good, { alg: 'none', kid: 'k' }), jwks, c)));
test('reject modified payload', () => { const [h, , s] = jwt().split('.'); assert.throws(() => verifyIdentity(h + '.' + enc({ ...good, id: 999 }) + '.' + s, jwks, c)); });
test('reject unknown signing key', () => assert.throws(() => verifyIdentity(jwt(good, { alg: 'RS256', kid: 'different' }), jwks, c)));

// Nonce: Telegram documents nonce for the Login library; the discovery document
// does not list it, so verification is conditional — enforced when echoed.
test('nonce match passes', () => assert.equal(verifyIdentity(jwt({ ...good, nonce: NONCE }), jwks, { ...c, nonce: NONCE }), '5678'));
test('nonce mismatch is rejected', () => assert.throws(() => verifyIdentity(jwt({ ...good, nonce: random() }), jwks, { ...c, nonce: NONCE }), /Nonce mismatch/));
test('nonce absent from token is tolerated (conditional verification)', () => assert.equal(verifyIdentity(jwt(), jwks, { ...c, nonce: NONCE }), '5678'));
test('nonce claim ignored when the flow sent none', () => assert.equal(verifyIdentity(jwt({ ...good, nonce: NONCE }), jwks, c), '5678'));

test('sealed flow round-trips state, verifier and nonce; tamper and expiry rejected', () => {
  const key = randomBytes(32).toString('hex');
  const data = { state: random(), verifier: random(), nonce: random(), exp: Date.now() + 10000 };
  const v = seal(data, key);
  assert.deepEqual(unseal(v, key), data);
  assert.throws(() => unseal(v, key, Date.now() + 11000));
  const buf = Buffer.from(v, 'base64url'); buf[15] ^= 1;
  assert.throws(() => unseal(buf.toString('base64url'), key));
  assert.throws(() => unseal(v, randomBytes(32).toString('hex')));
  assert.throws(() => unseal(seal({ state: random(), verifier: random(), nonce: 'short', exp: Date.now() + 10000 }, key), key));
});
test('PKCE challenge matches RFC 7636 vector; hashes and secrets are well-formed', () => {
  assert.equal(challenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'), 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  assert.match(hash(random()), /^[a-f0-9]{64}$/);
  assert.equal(validSecret(random()), true);
  assert.equal(validSecret('too-short'), false);
});
