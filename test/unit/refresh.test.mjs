// Refresh tokens (src/lib/refresh.js): who gets one, what the token response says about it, and the
// sealed token itself. The grant runs end to end in test/e2e, not here.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import config from '../../config.js';
import { newSecret } from '../../src/lib/sealed.js';
import { refreshGranted, grantedScope, mintRefreshToken, openRefreshToken } from '../../src/lib/refresh.js';

const confidential = { confidential: true };
const publicClient = { confidential: false };
const slotA = { slot: 'A', sealingSecret: newSecret() };
const slotB = { slot: 'B', sealingSecret: newSecret() };
const session = {
  client_id: 'r_s', scope: 'openid offline_access', device: 'tag',
  claims: { sub: 'john@example.com', auth_time: 1777454675, name: 'John Doe', groups: [] },
  exp: 1777454675 + 604800, cap: 1777454675 + 2592000,
};

/** Runs a test with the bridge's refresh tokens switched off. */
function withRefreshOff(fn) {
  config.refreshTokens = false;
  try { fn(); } finally { config.refreshTokens = true; }
}

test('a refresh token goes to an app with a secret that asked for offline_access, while the bridge issues them', () => {
  assert.equal(refreshGranted('openid email offline_access', confidential), true);
  assert.equal(refreshGranted('openid email', confidential), false);
  assert.equal(refreshGranted('openid offline_access', publicClient), false);
  assert.equal(refreshGranted('openid offline_accessx', confidential), false, 'whole words only');
  withRefreshOff(() => assert.equal(refreshGranted('openid offline_access', confidential), false));
});

test('the granted scope drops offline_access exactly when no refresh token comes with it', () => {
  assert.equal(grantedScope('openid email offline_access', confidential), 'openid email offline_access');
  assert.equal(grantedScope('openid offline_access email', publicClient), 'openid email');
  assert.equal(grantedScope('openid', publicClient), 'openid');
  withRefreshOff(() => assert.equal(grantedScope('openid offline_access', confidential), 'openid'));
});

test('a token names its slot, opens under that slot for its domain only, and carries the session unchanged', async () => {
  const token = await mintRefreshToken(slotA, 'example.com', session);
  assert.match(token, /^A\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+$/);
  assert.deepEqual(await openRefreshToken(token, [slotB, slotA], 'example.com'), session);
  assert.equal(await openRefreshToken(token, [slotB], 'example.com'), null, 'the slot is gone');
  assert.equal(await openRefreshToken(token, [slotA], 'other.com'), null, 'another domain');
  assert.equal(await openRefreshToken(token, [{ slot: 'A', sealingSecret: newSecret() }], 'example.com'), null, 'the slot was refilled');
  assert.equal(await openRefreshToken('B' + token.slice(1), [slotA, slotB], 'example.com'), null, 'the wrong slot named');
  assert.equal(await openRefreshToken(token.slice(0, -1) + (token.endsWith('A') ? 'B' : 'A'), [slotA], 'example.com'), null, 'a changed byte');
  for (const bad of ['', 'A', 'A.x', token + '.x', 42, null, undefined]) {
    assert.equal(await openRefreshToken(bad, [slotA], 'example.com'), null, String(bad));
  }
});

test('a token must carry a session: the app, the scope, the device, the claims with their subject, and both expiries', async () => {
  const minted = (changes) => mintRefreshToken(slotA, 'example.com', { ...session, ...changes });
  for (const changes of [{ exp: 'soon' }, { cap: NaN }, { client_id: undefined }, { device: 7 }, { claims: {} }, { claims: 'john' }]) {
    assert.equal(await openRefreshToken(await minted(changes), [slotA], 'example.com'), null, JSON.stringify(changes));
  }
});
