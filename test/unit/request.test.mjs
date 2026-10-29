// The authorization request (src/lib/request.js): every rule, one by one, and what travels on.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseAuthorizationRequest, carriedFields, returnUrl, CARRIED } from '../../src/lib/request.js';
import { createCredentials } from '../../src/lib/credentials.js';
import { providerFor } from '../../src/lib/provider.js';

const provider = providerFor('https://oidc.triauth.org', 'example.com');
const URI = 'https://grafana.example.com/login/generic_oauth';
const confidential = await createCredentials('example.com', URI);
const pub = await createCredentials('example.com', 'https://cli.example.com/cb', { secret: false });

function params(overrides = {}, base = { client_id: confidential.clientId, redirect_uri: URI, response_type: 'code', scope: 'openid email', state: 'st', nonce: 'nn' }) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries({ ...base, ...overrides })) {
    if (v !== undefined) { p.set(k, v); }
  }
  return p;
}

test('a well-formed request passes and carries the fields the sign-in needs', async () => {
  const result = await parseAuthorizationRequest(params(), provider);
  assert.equal(result.ok, true);
  assert.equal(result.client.host, 'grafana.example.com');
  assert.deepEqual(result.request, { response_type: 'code', client_id: confidential.clientId, redirect_uri: URI, scope: 'openid email', state: 'st', nonce: 'nn', code_challenge: undefined, code_challenge_method: undefined, response_mode: 'query', login_hint: undefined });
  assert.deepEqual(carriedFields(result.request), [['response_type', 'code'], ['client_id', confidential.clientId], ['redirect_uri', URI], ['scope', 'openid email'], ['state', 'st'], ['nonce', 'nn'], ['response_mode', 'query']]);
  assert.deepEqual(CARRIED, ['response_type', 'client_id', 'redirect_uri', 'scope', 'state', 'nonce', 'code_challenge', 'code_challenge_method', 'response_mode']);
});

test('without a known client there is no way back (returnTo is null)', async () => {
  for (const [name, p] of [
    ['no client_id', params({ client_id: undefined })],
    ['no redirect_uri', params({ redirect_uri: undefined })],
    ['bad redirect_uri', params({ redirect_uri: 'http://grafana.example.com/x' })],
    ['other redirect_uri', params({ redirect_uri: 'https://grafana.example.com/other' })],
    ['other domain', params({ client_id: (await createCredentials('other.com', URI)).clientId })],
    ['garbage client_id', params({ client_id: 'nope' })],
    ['duplicate client_id', (() => { const p = params(); p.append('client_id', confidential.clientId); return p; })()],
    ['oversized state', params({ state: 'x'.repeat(5000) })],
  ]) {
    const result = await parseAuthorizationRequest(p, provider);
    assert.equal(result.ok, false, name);
    assert.equal(result.returnTo, null, name);
    assert.equal(result.error, 'invalid_request', name);
  }
});

test('with a known client, later errors offer a way back with the state', async () => {
  const cases = [
    ['unsupported_response_type', params({ response_type: 'token' })],
    ['unsupported_response_type', params({ response_type: undefined })],
    ['invalid_scope', params({ scope: 'openid "quoted"' })],
    ['invalid_request', params({ code_challenge: 'short' })],
    ['invalid_request', params({ code_challenge: 'a'.repeat(43), code_challenge_method: 'plain' })],
    ['invalid_request', params({ code_challenge: 'a'.repeat(43) })],
    ['invalid_request', params({ code_challenge_method: 'S256' })],
    ['invalid_request', params({ response_mode: 'fragment' })],
    ['login_required', params({ prompt: 'none' })],
    ['login_required', params({ prompt: 'login none' })],
    ['request_not_supported', params({ request: 'eyJ' })],
    ['request_uri_not_supported', params({ request_uri: 'https://x/y' })],
  ];
  for (const [error, p] of cases) {
    const result = await parseAuthorizationRequest(p, provider);
    assert.equal(result.ok, false, error);
    assert.equal(result.error, error, p.toString());
    assert.deepEqual(result.returnTo, { redirect_uri: URI, state: 'st', response_mode: 'query' }, error);
  }
  // An app that takes its result as a form post gets its errors the same way.
  const formPost = await parseAuthorizationRequest(params({ response_type: 'token', response_mode: 'form_post' }), provider);
  assert.equal(formPost.error, 'unsupported_response_type');
  assert.deepEqual(formPost.returnTo, { redirect_uri: URI, state: 'st', response_mode: 'form_post' });
});

test('a public client must send a PKCE challenge; a confidential one may', async () => {
  const base = { client_id: pub.clientId, redirect_uri: 'https://cli.example.com/cb', response_type: 'code' };
  const without = await parseAuthorizationRequest(params({}, base), provider);
  assert.equal(without.ok, false);
  assert.equal(without.error, 'invalid_request');
  assert.match(without.description, /PKCE/);
  const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
  const withChallenge = await parseAuthorizationRequest(params({ code_challenge: challenge, code_challenge_method: 'S256' }, base), provider);
  assert.equal(withChallenge.ok, true);
  assert.equal(withChallenge.request.code_challenge, challenge);
  assert.equal(withChallenge.request.code_challenge_method, 'S256');
  assert.equal(withChallenge.client.confidential, false);
  const confidentialWith = await parseAuthorizationRequest(params({ code_challenge: challenge, code_challenge_method: 'S256' }), provider);
  assert.equal(confidentialWith.ok, true);
});

test('a public client needs a domain name or localhost in its redirect URI; a confidential one may use an IP address', async () => {
  // createCredentials does not apply the rule, as a client ID computed without the form would not.
  const IP = 'https://192.168.0.254:8006';
  const pkce = { code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256' };
  const ipPublic = await createCredentials('example.com', IP, { secret: false });
  const refused = await parseAuthorizationRequest(params(pkce, { client_id: ipPublic.clientId, redirect_uri: IP, response_type: 'code', state: 'st' }), provider);
  assert.equal(refused.ok, false);
  assert.equal(refused.error, 'unauthorized_client');
  assert.match(refused.description, /needs a domain name in its redirect URI/);
  assert.deepEqual(refused.returnTo, { redirect_uri: IP, state: 'st', response_mode: 'query' });
  const ipConfidential = await createCredentials('example.com', IP);
  assert.equal((await parseAuthorizationRequest(params({}, { client_id: ipConfidential.clientId, redirect_uri: IP, response_type: 'code' }), provider)).ok, true);
});

test('defaults: scope openid, response_mode query; prompt login is ignored', async () => {
  const result = await parseAuthorizationRequest(params({ scope: undefined, prompt: 'login consent' }), provider);
  assert.equal(result.ok, true);
  assert.equal(result.request.scope, 'openid');
  assert.equal(result.request.response_mode, 'query');
  const formPost = await parseAuthorizationRequest(params({ response_mode: 'form_post' }), provider);
  assert.equal(formPost.request.response_mode, 'form_post');
});

test('login_hint becomes a username only when it is one at this domain', async () => {
  const hint = async (login_hint) => (await parseAuthorizationRequest(params({ login_hint }), provider)).request.login_hint;
  assert.equal(await hint('john'), 'john');
  assert.equal(await hint('John@Example.com'), 'john');
  assert.equal(await hint('john@other.com'), undefined);
  assert.equal(await hint('not a user'), undefined);
  assert.equal(await hint('<script>'), undefined);
  assert.equal(await hint(''), undefined);
});

test('returnUrl appends to an existing query and skips undefined values', () => {
  assert.equal(returnUrl('https://app.example.com/cb', { code: 'c', state: 's', iss: 'https://oidc.triauth.org/example.com', nonce: undefined }),
    'https://app.example.com/cb?code=c&state=s&iss=https%3A%2F%2Foidc.triauth.org%2Fexample.com');
  assert.equal(returnUrl('https://app.example.com/cb?a=1', { code: 'c' }), 'https://app.example.com/cb?a=1&code=c');
  assert.equal(returnUrl('https://app.example.com/cb', { error: 'access_denied', state: 'a b&c' }), 'https://app.example.com/cb?error=access_denied&state=a+b%26c');
});
