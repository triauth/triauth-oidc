// Sealed records (src/lib/sealed.js): the secret opens its record and nothing else does.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { seal, open, newSecret, nameFor, SECRET_LENGTH } from '../../src/lib/sealed.js';

const binding = { kind: 'signin', domain: 'example.com' };

test('a record round-trips under its secret, and its name is the hash of the secret', async () => {
  const secret = newSecret();
  assert.equal(secret.length, SECRET_LENGTH);
  const { name, blob } = await seal(secret, binding, { a: 1, b: 'two' });
  assert.equal(name, await nameFor('signin', secret));
  assert.match(name, /^signin:[A-Za-z0-9_-]{43}$/);
  assert.equal((await seal(secret, { kind: 'code', domain: 'example.com' }, { a: 1 })).name, await nameFor('code', secret));
  assert.notEqual(await nameFor('code', secret), name, 'a secret of one kind never finds a record of the other');
  assert.match(blob, /^[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+$/);
  assert.deepEqual(await open(secret, binding, blob), { a: 1, b: 'two' });
});

test('another secret, another kind, another domain, or a changed blob opens nothing', async () => {
  const secret = newSecret();
  const { blob } = await seal(secret, binding, { a: 1 });
  assert.equal(await open(newSecret(), binding, blob), null);
  assert.equal(await open(secret, { kind: 'code', domain: 'example.com' }, blob), null);
  assert.equal(await open(secret, { kind: 'signin', domain: 'other.com' }, blob), null);
  const flipped = blob.slice(0, -1) + (blob.endsWith('A') ? 'B' : 'A');
  assert.equal(await open(secret, binding, flipped), null);
  assert.equal(await open(secret, binding, blob + '.x'), null);
  assert.equal(await open(secret, binding, ''), null);
  assert.equal(await open('short', binding, blob), null);
});

test('two seals of the same record differ (fresh IV), and names are secret-specific', async () => {
  const secret = newSecret();
  const one = await seal(secret, binding, { a: 1 });
  const two = await seal(secret, binding, { a: 1 });
  assert.notEqual(one.blob, two.blob);
  assert.equal(one.name, two.name);
  assert.notEqual(await nameFor('signin', newSecret()), one.name);
});

test('nameFor rejects anything that is not 32 canonical base64url bytes', async () => {
  assert.equal(await nameFor('signin', 'not base64url!'), null);
  assert.equal(await nameFor('signin', 'AAAA'), null);
  assert.equal(await nameFor('signin', newSecret() + 'A'), null);
  assert.notEqual(await nameFor('signin', newSecret()), null);
});
