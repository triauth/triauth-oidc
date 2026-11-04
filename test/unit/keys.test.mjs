// Signing keys (src/lib/keys.js): the slots, which one signs, the JWKS, and the sealing secret that
// each slot derives from its key for refresh tokens.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadKeys, publishedJwks } from '../../src/lib/keys.js';

async function privateJwk() {
  const pair = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  return JSON.stringify(await crypto.subtle.exportKey('jwk', pair.privateKey));
}

test('each filled slot carries its key, its kid, and a sealing secret that follows from the key alone', async () => {
  const a = await privateJwk();
  const b = await privateJwk();
  const keys = await loadKeys({ SIGNING_KEY_A: a, SIGNING_KEY_B: b, SIGNING_KEY_ACTIVE: 'B' });
  assert.equal(keys.signing.slot, 'B');
  assert.deepEqual(keys.published.map((key) => key.slot), ['A', 'B']);
  for (const slot of keys.published) {
    assert.match(slot.kid, /^[A-Za-z0-9_-]{43}$/);
    assert.match(slot.sealingSecret, /^[A-Za-z0-9_-]{43}$/, 'a record secret in the shape sealed.js takes');
  }
  assert.notEqual(keys.published[0].sealingSecret, keys.published[1].sealingSecret);
  assert.equal((await loadKeys({ SIGNING_KEY_A: a })).signing.sealingSecret, keys.published[0].sealingSecret, 'the same key gives the same secret');
  assert.equal((await loadKeys({ SIGNING_KEY_B: a })).signing.sealingSecret, keys.published[0].sealingSecret, 'in whichever slot');

  const jwks = await publishedJwks({ SIGNING_KEY_A: a });
  assert.equal(jwks.keys.length, 1);
  assert.equal(jwks.keys[0].kid, keys.published[0].kid);
  assert.equal(jwks.keys[0].d, undefined);
  assert.equal(jwks.keys[0].sealingSecret, undefined);
});

test('an empty or unreadable slot is left out, and the other slot signs when the active one is empty', async () => {
  const a = await privateJwk();
  const keys = await loadKeys({ SIGNING_KEY_A: a, SIGNING_KEY_B: '{"kty":"RSA"}', SIGNING_KEY_ACTIVE: 'B' });
  assert.equal(keys.signing.slot, 'A');
  assert.equal(keys.published.length, 1);
  assert.deepEqual(await loadKeys({ SIGNING_KEY_A: ' ' }), { signing: null, published: [] });
});
