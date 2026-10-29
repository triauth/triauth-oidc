// HTTP helpers (src/lib/http.js) and the token endpoint's client authentication (src/endpoints/token.js).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCookies, readForm, sameOrigin, cookie, withCors, json, redirect, rateKey } from '../../src/lib/http.js';
import { clientAuthentication } from '../../src/endpoints/token.js';

test('cookies parse verbatim', () => {
  assert.deepEqual(parseCookies('a=1; __Host-triauth_f_x=Zm9v; b=c=d; =bad; novalue'), { a: '1', '__Host-triauth_f_x': 'Zm9v', b: 'c=d' });
  assert.deepEqual(parseCookies(null), {});
});

test('readForm accepts small url-encoded bodies only', async () => {
  const form = await readForm(new Request('https://x/', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' }, body: 'a=1&b=%20x' }));
  assert.equal(form.get('a'), '1');
  assert.equal(form.get('b'), ' x');
  assert.equal(await readForm(new Request('https://x/', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })), null);
  assert.equal(await readForm(new Request('https://x/', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'a='.padEnd(70000, 'x') })), null);
  // A streamed body without Content-Length stops being read once it passes the cap.
  let pulled = 0;
  const stream = new ReadableStream({ pull(controller) { pulled += 1; controller.enqueue(new Uint8Array(16 * 1024).fill(120)); } });
  assert.equal(await readForm(new Request('https://x/', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: stream, duplex: 'half' })), null);
  assert.ok(pulled <= 6, `read ${pulled} chunks before stopping`);
});

test('rate limits count by IPv4 address or IPv6 /64', () => {
  const key = (ip) => rateKey(new Request('https://x/', { headers: ip ? { 'CF-Connecting-IP': ip } : {} }));
  assert.equal(key('203.0.113.9'), '203.0.113.9');
  assert.equal(key(null), 'local');
  assert.equal(key('2001:db8:85a3::8a2e:370:7334'), '2001:0db8:85a3:0000::/64');
  assert.equal(key('2001:DB8:85A3:0:1:2:3:4'), '2001:0db8:85a3:0000::/64');
  assert.equal(key('2001:db8:85a3:1::1'), '2001:0db8:85a3:0001::/64');
  assert.equal(key('::1'), '0000:0000:0000:0000::/64');
});

test('sameOrigin passes an absent Origin and the exact origin only', () => {
  const req = (origin) => new Request('https://oidc.test/x', { method: 'POST', headers: origin === undefined ? {} : { Origin: origin } });
  assert.equal(sameOrigin(req(undefined), 'https://oidc.test'), true);
  assert.equal(sameOrigin(req('https://oidc.test'), 'https://oidc.test'), true);
  assert.equal(sameOrigin(req('https://evil.test'), 'https://oidc.test'), false);
  assert.equal(sameOrigin(req('null'), 'https://oidc.test'), false);
});

test('cookies, redirects, json and CORS carry the intended attributes', () => {
  assert.equal(cookie('__Host-triauth_f_abc', 'v', 190, 'None'), '__Host-triauth_f_abc=v; Max-Age=190; Path=/; Secure; HttpOnly; SameSite=None');
  const r = redirect('https://app/cb', [cookie('__Host-x', '', 0, 'None')]);
  assert.equal(r.status, 302);
  assert.equal(r.headers.get('Location'), 'https://app/cb');
  assert.equal(r.headers.get('Cache-Control'), 'no-store');
  const j = json({ a: 1 }, 201);
  assert.equal(j.status, 201);
  assert.equal(j.headers.get('Cache-Control'), 'no-store');
  assert.equal(j.headers.get('X-Content-Type-Options'), 'nosniff');
  assert.equal(withCors(j).headers.get('Access-Control-Allow-Origin'), '*');
});

const form = (fields) => new URLSearchParams(fields);
const basic = (id, secret) => new Request('https://x/token', { method: 'POST', headers: { Authorization: 'Basic ' + Buffer.from(`${id}:${secret}`).toString('base64') } });
const bare = () => new Request('https://x/token', { method: 'POST' });

test('client authentication: Basic, form, percent-encoding, and conflicts', () => {
  // The client IDs are placeholders shaped like r_s and r; this layer does not read them.
  assert.deepEqual(clientAuthentication(basic('r_s', 'sec'), form({})), { client_id: 'r_s', client_secret: 'sec', basic: true });
  assert.deepEqual(clientAuthentication(basic('r%5Fs', 'sec'), form({})), { client_id: 'r_s', client_secret: 'sec', basic: true });
  assert.deepEqual(clientAuthentication(bare(), form({ client_id: 'r_s', client_secret: 'sec' })), { client_id: 'r_s', client_secret: 'sec', basic: false });
  assert.deepEqual(clientAuthentication(bare(), form({ client_id: 'r' })), { client_id: 'r', client_secret: null, basic: false });
  assert.deepEqual(clientAuthentication(basic('r_s', 'sec'), form({ client_id: 'r_s' })), { client_id: 'r_s', client_secret: 'sec', basic: true }, 'client_id repeated in the form is fine when equal');
  assert.ok(clientAuthentication(basic('r_s', 'sec'), form({ client_id: 'other' })).error);
  assert.ok(clientAuthentication(basic('r_s', 'sec'), form({ client_secret: 'sec' })).error, 'two methods');
  assert.ok(clientAuthentication(bare(), form({})).error, 'no authentication');
  assert.ok(clientAuthentication(new Request('https://x/token', { method: 'POST', headers: { Authorization: 'Bearer x' } }), form({})).error);
  assert.ok(clientAuthentication(new Request('https://x/token', { method: 'POST', headers: { Authorization: 'Basic !!!' } }), form({})).error);
  assert.ok(clientAuthentication(new Request('https://x/token', { method: 'POST', headers: { Authorization: 'Basic ' + Buffer.from('nocolon').toString('base64') } }), form({})).error);
  assert.ok(clientAuthentication(new Request('https://x/token', { method: 'POST', headers: { Authorization: 'Basic ' + Buffer.from('a%ZZ:b').toString('base64') } }), form({})).error);
});
