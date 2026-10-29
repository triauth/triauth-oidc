// Keys and JWTs (src/lib/keys.js, src/lib/jwt.js): slots, kid, signing, and every verification rule.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadKeys, publishedJwks, thumbprint } from '../../src/lib/keys.js';
import { signJwt, verifyJwt, decodeJwt } from '../../src/lib/jwt.js';

async function freshJwk() {
  const pair = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  return JSON.stringify(await crypto.subtle.exportKey('jwk', pair.privateKey));
}

const A = await freshJwk();
const B = await freshJwk();
const expected = (env, over = {}) => ({ issuer: 'https://oidc.test/example.com', audience: 'client', typ: 'JWT', ...over });

test('the active slot signs, every filled slot is published, kid is the RFC 7638 thumbprint', async () => {
  const env = { SIGNING_KEY_A: A, SIGNING_KEY_B: B, SIGNING_KEY_ACTIVE: 'B' };
  const keys = await loadKeys(env);
  assert.equal(keys.signing.slot, 'B');
  assert.deepEqual(keys.published.map((k) => k.slot), ['A', 'B']);
  const jwks = await publishedJwks(env);
  assert.equal(jwks.keys.length, 2);
  for (const jwk of jwks.keys) {
    assert.deepEqual(Object.keys(jwk).sort(), ['alg', 'e', 'kid', 'kty', 'n', 'use']);
    assert.equal(jwk.kid, await thumbprint(jwk));
    assert.equal(jwk.d, undefined);
  }
  // RFC 7638 example thumbprint
  assert.equal(await thumbprint({ kty: 'RSA', e: 'AQAB', n: '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw' }),
    'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs');
});

test('an empty active slot falls back to the other filled slot; no slots means no signing key', async () => {
  const keys = await loadKeys({ SIGNING_KEY_B: B, SIGNING_KEY_ACTIVE: 'A' });
  assert.equal(keys.signing.slot, 'B');
  const none = await loadKeys({ SIGNING_KEY_ACTIVE: 'A' });
  assert.equal(none.signing, null);
  assert.deepEqual(none.published, []);
  const corrupt = await loadKeys({ SIGNING_KEY_A: '{"kty":"oct"}', SIGNING_KEY_B: B });
  assert.equal(corrupt.signing.slot, 'B');
});

test('a malformed slot is ignored, and its value never reaches the log', async () => {
  const pasted = '-----BEGIN PRIVATE KEY----- MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ';
  const lines = [];
  const original = console.error;
  console.error = (...args) => lines.push(args.join(' '));
  try {
    const keys = await loadKeys({ SIGNING_KEY_A: pasted, SIGNING_KEY_B: B, SIGNING_KEY_ACTIVE: 'B' });
    assert.equal(keys.signing.slot, 'B');
    assert.deepEqual(keys.published.map((k) => k.slot), ['B']);
  } finally {
    console.error = original;
  }
  assert.ok(lines.some((line) => line.includes('SIGNING_KEY_A')), 'the slot is named');
  for (const line of lines) {
    assert.equal(line.includes('BEGIN'), false, line);
    assert.equal(line.includes('MIIEvQ'), false, line);
  }
});

test('a token signs and verifies, and decodeJwt shows its parts', async () => {
  const env = { SIGNING_KEY_A: A };
  const keys = await loadKeys(env);
  const now = Math.floor(Date.now() / 1000);
  const token = await signJwt({ typ: 'JWT', kid: keys.signing.kid }, { iss: 'https://oidc.test/example.com', aud: 'client', sub: 'john@example.com', iat: now, exp: now + 60 }, keys.signing.privateKey);
  const decoded = decodeJwt(token);
  assert.deepEqual(decoded.header, { typ: 'JWT', kid: keys.signing.kid, alg: 'RS256' });
  assert.equal(decoded.payload.sub, 'john@example.com');
  const payload = await verifyJwt(token, { keys: keys.published, ...expected(env) });
  assert.equal(payload.sub, 'john@example.com');
  assert.equal(decodeJwt('a.b'), null);
  assert.equal(decodeJwt('not.a.jwt'), null);
});

test('verification refuses the wrong key, typ, issuer, audience, expiry, alg, and tampering', async () => {
  const envA = { SIGNING_KEY_A: A };
  const keysA = await loadKeys(envA);
  const keysB = await loadKeys({ SIGNING_KEY_A: B });
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: 'https://oidc.test/example.com', aud: 'client', sub: 'john@example.com', iat: now, exp: now + 60 };
  const sign = (header, payload, key = keysA.signing) => signJwt(header, payload, key.privateKey);
  const header = { typ: 'JWT', kid: keysA.signing.kid };
  const good = await sign(header, claims);

  assert.ok(await verifyJwt(good, { keys: keysA.published, ...expected() }));
  assert.equal(await verifyJwt(good, { keys: keysB.published, ...expected() }), null, 'another key set');
  assert.equal(await verifyJwt(good, { keys: keysA.published, ...expected({}, { typ: 'at+jwt' }) }), null, 'typ');
  assert.equal(await verifyJwt(good, { keys: keysA.published, ...expected({}, { issuer: 'https://oidc.test/other.com' }) }), null, 'issuer');
  assert.equal(await verifyJwt(good, { keys: keysA.published, ...expected({}, { audience: 'other' }) }), null, 'audience');
  assert.equal(await verifyJwt(await sign(header, { ...claims, exp: now - 1 }), { keys: keysA.published, ...expected() }), null, 'expired');
  assert.equal(await verifyJwt(await sign(header, { ...claims, iat: now + 3600 }), { keys: keysA.published, ...expected() }), null, 'iat in the future');
  assert.equal(await verifyJwt(await sign(header, { ...claims, exp: 'soon' }), { keys: keysA.published, ...expected() }), null, 'exp not a number');
  assert.equal(await verifyJwt(await sign({ ...header, kid: 'unknown' }, claims), { keys: keysA.published, ...expected() }), null, 'unknown kid');
  assert.equal(await verifyJwt(await sign({ ...header, kid: undefined }, claims), { keys: keysA.published, ...expected() }), null, 'no kid');

  // alg confusion: a header claiming HS256 or none with the same payload
  const [, payloadPart] = good.split('.');
  const none = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT', kid: keysA.signing.kid })).toString('base64url') + '.' + payloadPart + '.';
  assert.equal(await verifyJwt(none, { keys: keysA.published, ...expected() }), null, 'alg none');
  const hs = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT', kid: keysA.signing.kid })).toString('base64url') + '.' + payloadPart + '.' + good.split('.')[2];
  assert.equal(await verifyJwt(hs, { keys: keysA.published, ...expected() }), null, 'alg HS256');

  // tampered payload keeps the signature
  const tampered = good.split('.');
  tampered[1] = Buffer.from(JSON.stringify({ ...claims, sub: 'mallory@example.com' })).toString('base64url');
  assert.equal(await verifyJwt(tampered.join('.'), { keys: keysA.published, ...expected() }), null, 'tampered payload');
  assert.equal(await verifyJwt(good.slice(0, -3) + 'AAA', { keys: keysA.published, ...expected() }), null, 'tampered signature');

  // an array audience that includes the expected one passes
  assert.ok(await verifyJwt(await sign(header, { ...claims, aud: ['other', 'client'] }), { keys: keysA.published, ...expected() }));
});
