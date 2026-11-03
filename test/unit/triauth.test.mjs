// The triauth-js glue (src/lib/triauth.js): the texts for triauth's error codes, and the claims of a
// verified sign-in. The protocol itself runs end to end in test/e2e, not here.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ERROR_TEXT, errorText, claimsOf } from '../../src/lib/triauth.js';

// The codes triauth-js documents (README, "Error codes") that a sign-in through the bridge can meet.
const TRIAUTH_CODES = [
  'dns_unavailable', 'invalid_identifier', 'invalid_callback_url', 'domain_not_configured',
  'verification_failed', 'request_expired', 'request_denied', 'dnssec_required',
];
const BRIDGE_CODES = ['domain', 'delegated'];

test('every triauth code the bridge expects has a text of its own, and so do the two bridge rules', () => {
  for (const code of [...TRIAUTH_CODES, ...BRIDGE_CODES]) {
    assert.ok(Object.hasOwn(ERROR_TEXT, code) && ERROR_TEXT[code].length > 0, code);
    assert.equal(errorText(code), ERROR_TEXT[code]);
  }
  assert.deepEqual(Object.keys(ERROR_TEXT).sort(), [...TRIAUTH_CODES, ...BRIDGE_CODES].sort(), 'no stale code in the table');
});

test('a code the table does not know gets a generic text that names it, never a prototype member', () => {
  assert.equal(errorText('invalid_response'), 'The sign-in failed (invalid_response). Please try again.');
  assert.equal(errorText('constructor'), 'The sign-in failed (constructor). Please try again.');
  assert.equal(errorText(401), 'The sign-in failed (401). Please try again.', 'the numeric codes of older triauth-js are gone');
});

test('claims carry the identity and its username, its groups, the DNSSEC result and the time, and a name only when published', () => {
  const result = { identifier: 'john@example.com', groups: ['admins@example.com'], secure: true, verifiedAt: 1777454675123 };
  assert.deepEqual(claimsOf(result), {
    sub: 'john@example.com',
    email: 'john@example.com',
    email_verified: true,
    preferred_username: 'john',
    groups: ['admins@example.com'],
    triauth_secure: true,
    auth_time: 1777454675,
  });
  const named = claimsOf({ ...result, secure: false, publicProfile: { name: 'John Doe' } });
  assert.equal(named.name, 'John Doe');
  assert.equal(named.triauth_secure, false);
  assert.equal(claimsOf({ ...result, publicProfile: { name: '' } }).name, undefined);
});
