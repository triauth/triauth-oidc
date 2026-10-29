// End-to-end flows: the real Worker in workerd, two fake DoH servers, a scripted authenticator, and
// openid-client as the app. The tests are grouped by the invariant they prove (PLAN.md, section 1):
//
//   I1  a token from issuer https://oidc.test/D names only identities at exactly D
//   I2  a code goes only to the redirect URI that its client ID was made for
//   I3  each triauth challenge and each code is used at most once
//   I4  stored records expire within minutes and cannot be read without the cookie or the code
//   I5  the bridge sends the browser to an app only after the user saw the app's address and acted

import { describe, it, expect } from 'vitest';
import { env, runInDurableObject, runDurableObjectAlarm } from 'cloudflare:test';
import { BASE, DOMAIN, makeJar, req, hiddenFields } from './client.js';
import { JOHN_DESKTOP, JOHN_LAPTOP, challengeFrom, callbackUrlOf, manifestOf, approve } from './authenticator.js';
import { discover, startAuthorization, oidc } from './rp.js';
import { createCredentials } from '../../src/lib/credentials.js';
import { decodeJwt } from '../../src/lib/jwt.js';
import worker from '../../src/index.js';

const ISSUER = `${BASE}/${DOMAIN}`;
const APP = 'https://grafana.example.com/login/generic_oauth';
const APP_HOST = 'grafana.example.com';
const JOHN = 'john@triauthdemo.org';

// ------------------------------------------------------------------------------ helpers --

/** The browser's part of a sign-in: open the authorization URL, submit the username, approve. */
async function browserSignIn(jar, authUrl, { username = 'john', identifier = JOHN, keys = JOHN_DESKTOP, host = APP_HOST, domain = DOMAIN, actor = '', answer = null } = {}) {
  const page = await req(jar, 'GET', authUrl.toString());
  expect(page.status).toBe(200);
  const fields = hiddenFields(await page.text());
  const login = await req(jar, 'POST', `/${domain}/login`, { headers: { Origin: BASE }, form: { ...fields, username } });
  if (login.status !== 302) {
    expect.fail(`stage 1 should redirect to the authenticator, got ${login.status}: ${pageText(await login.text())}`);
  }
  const challenge = challengeFrom(login.headers.get('location'));
  expect(challenge).toBeTruthy();
  const response = answer ?? await approve(challenge, { identifier, keys, host, domain, actor });
  return { callback: await req(jar, 'POST', callbackUrlOf(challenge), { form: { response } }), challenge, response };
}

/** Credentials for the app, discovery by openid-client, and the authorization URL. */
async function prepare({ method = 'basic', redirectUri = APP, domain = DOMAIN, group = null, extra = {} } = {}) {
  const creds = await createCredentials(domain, redirectUri, { secret: method !== 'none', group });
  const config = await discover(`${BASE}/${domain}`, creds.clientId, { secret: creds.clientSecret ?? undefined, method });
  const { url, checks } = await startAuthorization(config, redirectUri, extra);
  return { creds, config, url, checks };
}

/** A complete sign-in up to and including the app's token exchange. */
async function fullSignIn(options = {}) {
  const { creds, config, url, checks } = await prepare(options);
  const jar = makeJar();
  const { callback } = await browserSignIn(jar, url, { host: new URL(options.redirectUri ?? APP).host, domain: options.domain ?? DOMAIN, ...(options.browser || {}) });
  expect(callback.status, 'the callback should redirect to the app').toBe(302);
  const location = new URL(callback.headers.get('location'));
  const tokens = await oidc.authorizationCodeGrant(config, location, checks);
  return { creds, config, checks, jar, tokens, location };
}

/** A sign-in that stops at the code, for tests that call /token by hand. */
async function obtainCode(options = {}) {
  const { creds, config, url, checks } = await prepare(options);
  const jar = makeJar();
  const { callback } = await browserSignIn(jar, url, { host: new URL(options.redirectUri ?? APP).host });
  expect(callback.status).toBe(302);
  const location = new URL(callback.headers.get('location'));
  return { creds, config, checks, jar, location, code: location.searchParams.get('code') };
}

/** The sentences of a page, for failure messages. */
function pageText(html) {
  return (html.match(/<(?:p|h1)[^>]*>([^<]*)</g) || []).map((m) => m.replace(/<[^>]*>/g, '')).filter(Boolean).join(' | ');
}

function tokenRequest(form, { basic = null, domain = DOMAIN } = {}) {
  const headers = basic ? { Authorization: 'Basic ' + btoa(`${basic.id}:${basic.secret}`) } : {};
  return req(makeJar(), 'POST', `/${domain}/token`, { headers, form });
}

const storeOf = (domain = DOMAIN) => env.STORE.get(env.STORE.idFromName(domain));
const storedRecords = (domain) => runInDurableObject(storeOf(domain), async (instance, state) => [...(await state.storage.list()).entries()]);

// ---------------------------------------------------------------------------- discovery --

describe('discovery and keys', () => {
  it('serves the discovery document with CORS and a short cache', async () => {
    const res = await req(makeJar(), 'GET', `/${DOMAIN}/.well-known/openid-configuration`);
    expect(res.status).toBe(200);
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
    expect(res.headers.get('cache-control')).toBe('public, max-age=300');
    const doc = await res.json();
    expect(doc.issuer).toBe(ISSUER);
    expect(doc.authorization_endpoint).toBe(`${ISSUER}/authorize`);
    expect(doc.token_endpoint).toBe(`${ISSUER}/token`);
    expect(doc.userinfo_endpoint).toBe(`${ISSUER}/userinfo`);
    expect(doc.jwks_uri).toBe(`${ISSUER}/jwks`);
    expect(doc.response_types_supported).toEqual(['code']);
    expect(doc.grant_types_supported).toEqual(['authorization_code']);
    expect(doc.id_token_signing_alg_values_supported).toEqual(['RS256']);
    expect(doc.code_challenge_methods_supported).toEqual(['S256']);
    expect(doc.token_endpoint_auth_methods_supported).toEqual(['client_secret_basic', 'client_secret_post', 'none']);
    expect(doc.end_session_endpoint).toBeUndefined();
  });

  it('publishes the signing key as a JWK Set, answers preflights, and 404s elsewhere', async () => {
    const jwks = await (await req(makeJar(), 'GET', `/${DOMAIN}/jwks`)).json();
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).toMatchObject({ kty: 'RSA', alg: 'RS256', use: 'sig' });
    expect(jwks.keys[0].kid).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(jwks.keys[0].d).toBeUndefined();

    const preflight = await req(makeJar(), 'OPTIONS', `/${DOMAIN}/token`);
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get('access-control-allow-methods')).toContain('POST');

    expect((await req(makeJar(), 'GET', `/${DOMAIN}/nothing`)).status).toBe(404);
    expect((await req(makeJar(), 'GET', '/Example.com/')).status).toBe(404);
    expect((await req(makeJar(), 'GET', `/${DOMAIN}/token`)).status).toBe(405);
    const bare = await req(makeJar(), 'GET', `/${DOMAIN}`);
    expect(bare.status).toBe(302);
    expect(bare.headers.get('location')).toBe(`/${DOMAIN}/`);
  });

  it('serves only the domains in DOMAINS when the variable is set', async () => {
    const limited = { ...env, DOMAINS: 'triauthdemo.org' };
    expect((await worker.fetch(new Request(`${BASE}/other.example/jwks`), limited)).status).toBe(404);
    expect((await worker.fetch(new Request(`${BASE}/${DOMAIN}/jwks`), limited)).status).toBe(200);
  });

  it('serves discovery at the RFC 8414 addresses too, and answers HEAD like GET without a body', async () => {
    const reference = await (await req(makeJar(), 'GET', `/${DOMAIN}/.well-known/openid-configuration`)).json();
    for (const path of [`/.well-known/openid-configuration/${DOMAIN}`, `/.well-known/oauth-authorization-server/${DOMAIN}`, `/${DOMAIN}/.well-known/oauth-authorization-server`]) {
      const res = await req(makeJar(), 'GET', path);
      expect(res.status, path).toBe(200);
      expect(res.headers.get('access-control-allow-origin')).toBe('*');
      expect(await res.json()).toEqual(reference);
    }
    expect((await req(makeJar(), 'OPTIONS', `/.well-known/openid-configuration/${DOMAIN}`)).status).toBe(204);
    expect((await req(makeJar(), 'GET', '/.well-known/openid-configuration/Not.A.Domain')).status).toBe(404);
    expect((await req(makeJar(), 'GET', '/.well-known/webfinger')).status).toBe(404);

    const head = await req(makeJar(), 'HEAD', `/${DOMAIN}/jwks`);
    expect(head.status).toBe(200);
    expect(head.headers.get('content-type')).toContain('application/json');
    expect(await head.text()).toBe('');
    expect((await req(makeJar(), 'HEAD', '/')).status).toBe(200);
    expect((await req(makeJar(), 'HEAD', `/${DOMAIN}/token`)).status).toBe(405);
  });

  it('a rotation, step by step: the new key is published first, signs after the flip, and the old one can be deleted', async () => {
    const { tokens } = await fullSignIn();   // signed by slot A, the active one
    const kidA = decodeJwt(tokens.access_token).header.kid;
    const pair = await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
    const keyB = JSON.stringify(await crypto.subtle.exportKey('jwk', pair.privateKey));
    const call = (path, init, overrides) => worker.fetch(new Request(`${BASE}${path}`, init), { ...env, ...overrides });
    const userinfo = (token, overrides) => call(`/${DOMAIN}/userinfo`, { headers: { Authorization: `Bearer ${token}` } }, overrides);

    // 1. The new key goes into slot B. Both keys are published, A first; A's tokens still verify.
    const step1 = { SIGNING_KEY_B: keyB };
    const jwks = await (await call(`/${DOMAIN}/jwks`, {}, step1)).json();
    expect(jwks.keys).toHaveLength(2);
    expect(jwks.keys[0].kid).toBe(kidA);
    expect((await userinfo(tokens.access_token, step1)).status).toBe(200);

    // 2. The flip. New tokens carry B's kid, and A's tokens still verify.
    const step2 = { SIGNING_KEY_B: keyB, SIGNING_KEY_ACTIVE: 'B' };
    const { creds, checks, code } = await obtainCode();
    const redeemed = await call(`/${DOMAIN}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'CF-Connecting-IP': '10.98.0.1', Authorization: 'Basic ' + btoa(`${creds.clientId}:${creds.clientSecret}`) },
      body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: APP, code_verifier: checks.pkceCodeVerifier }).toString(),
    }, step2);
    expect(redeemed.status).toBe(200);
    const fresh = await redeemed.json();
    const kidB = decodeJwt(fresh.access_token).header.kid;
    expect(kidB).toBe(jwks.keys[1].kid);
    expect((await userinfo(tokens.access_token, step2)).status).toBe(200);
    expect((await userinfo(fresh.access_token, step2)).status).toBe(200);

    // 3. Slot A is deleted, as after a leak. Its tokens stop working at once; B's keep working.
    const step3 = { SIGNING_KEY_A: undefined, SIGNING_KEY_B: keyB, SIGNING_KEY_ACTIVE: 'B' };
    expect((await (await call(`/${DOMAIN}/jwks`, {}, step3)).json()).keys.map((k) => k.kid)).toEqual([kidB]);
    expect((await userinfo(tokens.access_token, step3)).status).toBe(401);
    expect((await userinfo(fresh.access_token, step3)).status).toBe(200);
  });
});

// -------------------------------------------------------------------------------- pages --

describe('the pages', () => {
  it('home page, and the domain form', async () => {
    expect((await req(makeJar(), 'GET', '/')).status).toBe(200);
    const go = await req(makeJar(), 'GET', '/?domain=John@TriauthDemo.org');
    expect(go.status).toBe(302);
    expect(go.headers.get('location')).toBe(`/${DOMAIN}/`);
    expect((await req(makeJar(), 'GET', '/robots.txt')).status).toBe(200);
    expect((await req(makeJar(), 'GET', '/favicon.ico')).headers.get('content-type')).toBe('image/svg+xml');
    const icon = await req(makeJar(), 'GET', '/favicon.svg');
    expect(icon.headers.get('content-type')).toBe('image/svg+xml');
    expect(await icon.text()).toContain('<path d="m 48.046615,144.18979');
  });

  it('the domain page reads the triauth record', async () => {
    const configured = await (await req(makeJar(), 'GET', `/${DOMAIN}/`)).text();
    expect(configured).not.toContain("isn't set up for triauth");
    expect(configured).not.toContain('class="badge'); // neither "Not set up" nor "Unknown": the record was read
    expect(configured).toContain(`${ISSUER}/.well-known/openid-configuration`);
    const unconfigured = await (await req(makeJar(), 'GET', '/unconfigured.example/')).text();
    expect(unconfigured).toContain("unconfigured.example isn't set up for triauth yet");
  });

  it('creates credentials from the form, and refuses bad redirect URIs and other origins', async () => {
    const res = await req(makeJar(), 'POST', `/${DOMAIN}/credentials`, { headers: { Origin: BASE }, form: { redirect_uri: APP } });
    expect(res.status).toBe(200);
    const html = await res.text();
    const clientId = html.match(/<code class="value">([a-z2-7]{26}_[a-z2-7]{26})<\/code>/)?.[1];
    expect(clientId).toBeTruthy();
    expect(html).toContain('[auth.generic_oauth]');
    expect(html).toContain(`client_id = ${clientId}`);
    expect(html).toMatch(/client_secret = [A-Za-z0-9_-]{43}\n/);
    expect(html).toContain(`everyone with an identifier under the <strong>@${DOMAIN}</strong> domain`);

    const pub = await (await req(makeJar(), 'POST', `/${DOMAIN}/credentials`, { headers: { Origin: BASE }, form: { redirect_uri: 'https://cli.example.com/cb', public: '1' } })).text();
    expect(pub).toMatch(/<code class="value">[a-z2-7]{26}<\/code>/);
    expect(pub).toContain('must use PKCE');

    const http = await req(makeJar(), 'POST', `/${DOMAIN}/credentials`, { headers: { Origin: BASE }, form: { redirect_uri: 'http://grafana.example.com/x' } });
    expect(http.status).toBe(400);
    expect(await http.text()).toContain('canonical https:// URL');
    const own = await req(makeJar(), 'POST', `/${DOMAIN}/credentials`, { headers: { Origin: BASE }, form: { redirect_uri: `${BASE}/${DOMAIN}/authorize` } });
    expect(own.status).toBe(400);
    expect(await own.text()).toContain('own host');
    const ipPublic = await req(makeJar(), 'POST', `/${DOMAIN}/credentials`, { headers: { Origin: BASE }, form: { redirect_uri: 'https://192.168.0.254:8006', public: '1' } });
    expect(ipPublic.status).toBe(400);
    expect(await ipPublic.text()).toContain('needs a domain name in its redirect URI');
    expect((await req(makeJar(), 'POST', `/${DOMAIN}/credentials`, { headers: { Origin: 'https://evil.test' }, form: { redirect_uri: APP } })).status).toBe(403);
  });

  it('limits sign-ins to a group from the form, and refuses a bad name with the form as it was sent', async () => {
    const form = (fields) => req(makeJar(), 'POST', `/${DOMAIN}/credentials`, { headers: { Origin: BASE }, form: { redirect_uri: APP, ...fields } });
    const res = await form({ limit_group: '1', group: ' Admins@TriauthDemo.org ' });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toMatch(/<code class="value">[a-z2-7]{26}_[a-z2-7]{26}_g-admins<\/code>/);
    expect(html).toContain(`members of the <strong>admins@${DOMAIN}</strong> group will be able to sign in`);

    // A name typed while the box is unchecked does not count.
    expect(await (await form({ group: 'admins' })).text()).toMatch(/<code class="value">[a-z2-7]{26}_[a-z2-7]{26}<\/code>/);

    for (const group of ['', 'admins_x', 'admins@other.example', 'a'.repeat(21)]) {
      const bad = await form({ limit_group: '1', group });
      expect(bad.status, group).toBe(400);
      const page = await bad.text();
      expect(page).toContain('<p class="err">');
      expect(page).toContain('name="limit_group" value="1" aria-describedby="limit_group_hint" checked>');
      expect(page).not.toMatch(/<code class="value">[a-z2-7]{26}/);   // no client ID was made
    }
  });
});

// -------------------------------------------------------------------------------- I1 --

describe('I1: a token names only identities at its domain', () => {
  it('a full sign-in gives the app an ID token, an access token, and userinfo for john@triauthdemo.org', async () => {
    const { creds, config, checks, tokens, location } = await fullSignIn();
    expect(location.origin + location.pathname).toBe(APP);
    expect(location.searchParams.get('iss')).toBe(ISSUER);
    expect(location.searchParams.get('state')).toBe(checks.expectedState);

    const claims = tokens.claims();
    expect(claims.iss).toBe(ISSUER);
    expect(claims.sub).toBe(JOHN);
    expect(claims.aud).toBe(creds.clientId);
    expect(claims.nonce).toBe(checks.expectedNonce);
    expect(claims.email).toBe(JOHN);
    expect(claims.email_verified).toBe(true);
    expect(claims.preferred_username).toBe(JOHN);
    expect(claims.name).toBe('John Doe');
    expect(claims.groups).toEqual(['admins@triauthdemo.org', 'dev@triauthdemo.org']);
    expect(claims.triauth_secure).toBe(true);
    expect(typeof claims.auth_time).toBe('number');
    expect(claims.exp - claims.iat).toBe(600);
    expect(tokens.token_type.toLowerCase()).toBe('bearer');
    expect(tokens.expires_in).toBe(3600);
    expect(tokens.scope).toBe('openid email profile groups');
    expect(tokens.refresh_token).toBeUndefined();

    const idHeader = decodeJwt(tokens.id_token).header;
    const atHeader = decodeJwt(tokens.access_token).header;
    expect(idHeader.typ).toBe('JWT');
    expect(atHeader.typ).toBe('at+jwt');
    expect(atHeader.kid).toBe(idHeader.kid);
    expect(decodeJwt(tokens.access_token).payload.aud).toBe(`${ISSUER}/userinfo`);

    const userinfo = await oidc.fetchUserInfo(config, tokens.access_token, claims.sub);
    expect(userinfo).toEqual({
      sub: JOHN, email: JOHN, email_verified: true, preferred_username: JOHN, name: 'John Doe',
      groups: ['admins@triauthdemo.org', 'dev@triauthdemo.org'], triauth_secure: true,
    });

    // The token may also come as a form field (RFC 6750 §2.2).
    const posted = await req(makeJar(), 'POST', `/${DOMAIN}/userinfo`, { form: { access_token: tokens.access_token } });
    expect(posted.status).toBe(200);
    expect((await posted.json()).sub).toBe(JOHN);
    expect(posted.headers.get('x-content-type-options')).toBe('nosniff');
  });

  it('another domain has its own issuer and vouches for its own identities', async () => {
    const { tokens } = await fullSignIn({ domain: 'other.example', redirectUri: 'https://app.other.example/cb', browser: { identifier: 'john@other.example' } });
    const claims = tokens.claims();
    expect(claims.iss).toBe(`${BASE}/other.example`);
    expect(claims.sub).toBe('john@other.example');
    expect(claims.groups).toEqual([]);
    expect(claims.name).toBeUndefined();
  });

  it('a response signed for an identity at another domain does not complete a sign-in here', async () => {
    const { url } = await prepare();
    const { callback } = await browserSignIn(makeJar(), url, { identifier: 'john@other.example' });
    expect(callback.status).toBe(400);
    expect(callback.headers.get('location')).toBeNull();
    expect(await callback.text()).toContain('could not be verified');
  });

  it("a code minted at one domain cannot be redeemed at another domain's token endpoint", async () => {
    const { creds, checks, code } = await obtainCode();
    const res = await tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: APP, code_verifier: checks.pkceCodeVerifier }, { basic: { id: creds.clientId, secret: creds.clientSecret }, domain: 'other.example' });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe('invalid_grant');
  });
});

// -------------------------------------------------------------------------------- I2 --

describe('I2: a code goes only to the redirect URI of its client ID', () => {
  it('an app at an IPv4 address whose redirect URI has no path signs in, as Proxmox VE does', async () => {
    // Proxmox VE sends its origin without the slash; openid-client sends the redirect_uri to /token
    // as the URL parser writes it, with the slash.
    const { tokens, location } = await fullSignIn({ redirectUri: 'https://192.168.0.254:8006' });
    expect(location.host).toBe('192.168.0.254:8006');
    expect(tokens.claims().sub).toBe(JOHN);
  });

  it('/authorize refuses a client ID with another redirect URI, and shows no way back', async () => {
    const creds = await createCredentials(DOMAIN, APP);
    const res = await req(makeJar(), 'GET', `/${DOMAIN}/authorize?response_type=code&client_id=${creds.clientId}&redirect_uri=${encodeURIComponent('https://grafana.example.com/login/other')}&state=s`);
    expect(res.status).toBe(400);
    expect(res.headers.get('location')).toBeNull();
    const html = await res.text();
    expect(html).toContain('was not made for');
    expect(html).not.toContain('Return to');
  });

  it('/authorize refuses a redirect URI on the bridge itself', async () => {
    const creds = await createCredentials(DOMAIN, APP);
    const own = `${BASE}/${DOMAIN}/authorize`;
    const res = await req(makeJar(), 'GET', `/${DOMAIN}/authorize?response_type=code&client_id=${creds.clientId}&redirect_uri=${encodeURIComponent(own)}`);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain('own host');
  });

  it('/token refuses the code with another redirect URI or another client', async () => {
    const { creds, checks, code } = await obtainCode();
    const verifier = checks.pkceCodeVerifier;
    const other = await tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: 'https://grafana.example.com/login/other', code_verifier: verifier }, { basic: { id: creds.clientId, secret: creds.clientSecret } });
    expect(other.status).toBe(400);
    expect((await other.json()).error).toBe('invalid_grant');

    const stranger = await createCredentials(DOMAIN, APP);   // the same redirect URI, its own secret
    const res = await tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: APP, code_verifier: verifier }, { basic: { id: stranger.clientId, secret: stranger.clientSecret } });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe('invalid_grant');
  });
});

// -------------------------------------------------------------------------------- I3 --

describe('I3: challenges and codes are single-use', () => {
  it('a replayed authenticator response finds nothing', async () => {
    const { url } = await prepare();
    const jar = makeJar();
    const fields = hiddenFields(await (await req(jar, 'GET', url.toString())).text());
    const login = await req(jar, 'POST', `/${DOMAIN}/login`, { headers: { Origin: BASE }, form: { ...fields, username: 'john' } });
    const challenge = challengeFrom(login.headers.get('location'));
    const [cookieName, cookieValue] = [...jar.cookies].find(([name]) => name.startsWith('__Host-triauth_f_'));
    const response = await approve(challenge, { identifier: JOHN, keys: JOHN_DESKTOP, host: APP_HOST });

    const first = await req(jar, 'POST', callbackUrlOf(challenge), { form: { response } });
    expect(first.status).toBe(302);
    expect(jar.cookies.has(cookieName)).toBe(false);

    // The same POST again, with the cookie a captured request would carry.
    const replay = await req(jar, 'POST', callbackUrlOf(challenge), { headers: { Cookie: `${cookieName}=${cookieValue}` }, form: { response } });
    expect(replay.status).toBe(400);
    expect(await replay.text()).toContain('expired');
  });

  it('a replayed code is refused', async () => {
    const { creds, checks, code } = await obtainCode();
    const basic = { id: creds.clientId, secret: creds.clientSecret };
    const form = { grant_type: 'authorization_code', code, redirect_uri: APP, code_verifier: checks.pkceCodeVerifier };
    const first = await tokenRequest(form, { basic });
    expect(first.status).toBe(200);
    expect((await first.json()).id_token).toBeTruthy();
    const second = await tokenRequest(form, { basic });
    expect(second.status).toBe(400);
    expect((await second.json()).error).toBe('invalid_grant');
  });

  it('twelve parallel redemptions of one code yield exactly one token', async () => {
    const { creds, checks, code } = await obtainCode();
    const basic = { id: creds.clientId, secret: creds.clientSecret };
    const form = { grant_type: 'authorization_code', code, redirect_uri: APP, code_verifier: checks.pkceCodeVerifier };
    const results = await Promise.all(Array.from({ length: 12 }, () => tokenRequest(form, { basic })));
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    expect(results.filter((r) => r.status === 400)).toHaveLength(11);
  });
});

// -------------------------------------------------------------------------------- I4 --

describe('I4: records are sealed, short-lived, and need the cookie', () => {
  it('a sign-in record reveals nothing without the cookie, and is gone once used', async () => {
    const { creds, checks, url } = await prepare();
    const before = new Set((await storedRecords()).map(([name]) => name));   // other tests leave records behind
    const newRecords = async () => (await storedRecords()).filter(([name]) => !before.has(name));
    const jar = makeJar();
    const page = await req(jar, 'GET', url.toString());
    const fields = hiddenFields(await page.text());
    const login = await req(jar, 'POST', `/${DOMAIN}/login`, { headers: { Origin: BASE }, form: { ...fields, username: 'john' } });
    expect(login.status).toBe(302);

    const records = await newRecords();
    expect(records).toHaveLength(1);
    const [name, value] = records[0];
    expect(name).toMatch(/^signin:[A-Za-z0-9_-]{43}$/);
    expect(value.exp).toBeGreaterThan(Date.now());
    expect(value.exp).toBeLessThanOrEqual(Date.now() + 190 * 1000);
    const cookie = [...jar.cookies.values()][0];
    expect(name).not.toBe(cookie);
    for (const secret of ['john', 'triauthdemo', creds.clientId, 'grafana', fields.state]) {
      expect(value.blob).not.toContain(secret);
    }

    const challenge = challengeFrom(login.headers.get('location'));
    const callback = await req(jar, 'POST', callbackUrlOf(challenge), { form: { response: await approve(challenge, { identifier: JOHN, keys: JOHN_DESKTOP, host: APP_HOST }) } });
    expect(callback.status).toBe(302);
    const afterCallback = await newRecords();
    expect(afterCallback).toHaveLength(1);   // the code
    expect(afterCallback[0][0]).toMatch(/^code:[A-Za-z0-9_-]{43}$/);

    const code = new URL(callback.headers.get('location')).searchParams.get('code');
    expect((await tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: APP, code_verifier: checks.pkceCodeVerifier }, { basic: { id: creds.clientId, secret: creds.clientSecret } })).status).toBe(200);
    expect(await newRecords()).toHaveLength(0);
  });

  it("the callback without this browser's cookie fails (login CSRF), and the sign-in survives for the real browser", async () => {
    const { url } = await prepare();
    const jar = makeJar();
    const fields = hiddenFields(await (await req(jar, 'GET', url.toString())).text());
    const login = await req(jar, 'POST', `/${DOMAIN}/login`, { headers: { Origin: BASE }, form: { ...fields, username: 'john' } });
    const challenge = challengeFrom(login.headers.get('location'));
    const response = await approve(challenge, { identifier: JOHN, keys: JOHN_DESKTOP, host: APP_HOST });

    const stranger = await req(makeJar(), 'POST', callbackUrlOf(challenge), { form: { response } });
    expect(stranger.status).toBe(400);
    expect(await stranger.text()).toContain('expired');
    expect(stranger.headers.get('location')).toBeNull();

    const owner = await req(jar, 'POST', callbackUrlOf(challenge), { form: { response } });
    expect(owner.status).toBe(302);
  });

  it('the purge alarm removes expired records and keeps live ones', async () => {
    await runInDurableObject(storeOf(), async (instance, state) => {
      await state.storage.put('expired', { blob: 'x', exp: Date.now() - 1000 });
      await state.storage.put('live', { blob: 'y', exp: Date.now() + 60000 });
      await state.storage.setAlarm(Date.now() + 1000);
    });
    expect(await runDurableObjectAlarm(storeOf())).toBe(true);
    const names = (await storedRecords()).map(([name]) => name);
    expect(names).toContain('live');
    expect(names).not.toContain('expired');
    expect(await runInDurableObject(storeOf(), (instance, state) => state.storage.getAlarm())).not.toBeNull();
  });
});

// -------------------------------------------------------------------------------- I5 --

describe('I5: no redirect to the app before the user acts', () => {
  it("the app's address on the bridge offers a link to the app's host, never a redirect, and only for a host an app could have", async () => {
    const tile = await req(makeJar(), 'GET', `/${DOMAIN}/apps/${APP_HOST}/`);
    expect(tile.status).toBe(200);
    expect(tile.headers.get('location')).toBeNull();
    expect(await tile.text()).toContain(`<a class="button" href="https://${APP_HOST}/" autofocus>Open ${APP_HOST}</a>`);

    const local = await req(makeJar(), 'GET', `/${DOMAIN}/apps/localhost:3000/`);
    expect(local.status).toBe(200);
    expect(await local.text()).toContain('<a class="button" href="http://localhost:3000/" autofocus>Open localhost:3000</a>');

    for (const host of [new URL(BASE).host, `x.${new URL(BASE).host}`, 'a..b', `${APP_HOST}:443`]) {
      const refused = await req(makeJar(), 'GET', `/${DOMAIN}/apps/${host}/`);
      expect(refused.status, host).toBe(404);
      expect(await refused.text()).not.toContain(`href="https://${host}/"`);
    }
  });

  it('a bad request from a known app gets a page with a link back, never a redirect', async () => {
    const creds = await createCredentials(DOMAIN, APP);
    const res = await req(makeJar(), 'GET', `/${DOMAIN}/authorize?response_type=token&client_id=${creds.clientId}&redirect_uri=${encodeURIComponent(APP)}&state=abc`);
    expect(res.status).toBe(400);
    expect(res.headers.get('location')).toBeNull();
    const html = await res.text();
    expect(html).toContain('Return to grafana.example.com');
    expect(html).toContain(`href="${APP}?error=unsupported_response_type&amp;error_description=`);
    expect(html).toContain('state=abc');
    expect(html).toContain(encodeURIComponent(ISSUER));

    const silent = await req(makeJar(), 'GET', `/${DOMAIN}/authorize?response_type=code&client_id=${creds.clientId}&redirect_uri=${encodeURIComponent(APP)}&prompt=none`);
    expect(silent.status).toBe(400);
    expect(await silent.text()).toContain('error=login_required');
  });

  it('a bad request from a form_post app gets a form the user submits, never a redirect', async () => {
    const creds = await createCredentials(DOMAIN, APP);
    const res = await req(makeJar(), 'GET', `/${DOMAIN}/authorize?response_type=token&response_mode=form_post&client_id=${creds.clientId}&redirect_uri=${encodeURIComponent(APP)}&state=abc`);
    expect(res.status).toBe(400);
    expect(res.headers.get('location')).toBeNull();
    expect(res.headers.get('content-security-policy')).toContain("script-src 'none'");
    const html = await res.text();
    expect(html).toContain(`<form method="post" action="${APP}">`);
    expect(html).toContain('<button type="submit">Return to grafana.example.com</button>');
    expect(hiddenFields(html)).toEqual({ error: 'unsupported_response_type', error_description: expect.any(String), state: 'abc', iss: ISSUER });
  });

  it('a declined sign-in goes back to the app with access_denied', async () => {
    const { url, checks } = await prepare();
    const { callback } = await browserSignIn(makeJar(), url, { answer: 'false' });
    expect(callback.status).toBe(302);
    const location = new URL(callback.headers.get('location'));
    expect(location.origin + location.pathname).toBe(APP);
    expect(location.searchParams.get('error')).toBe('access_denied');
    expect(location.searchParams.get('state')).toBe(checks.expectedState);
    expect(location.searchParams.get('iss')).toBe(ISSUER);
    expect(location.searchParams.get('code')).toBeNull();
  });

  it('response_mode=form_post hands the code to the app as a form, which openid-client accepts', async () => {
    const { config, url, checks } = await prepare({ extra: { response_mode: 'form_post' } });
    const { callback } = await browserSignIn(makeJar(), url);
    expect(callback.status).toBe(200);
    expect(callback.headers.get('content-security-policy')).toContain("script-src 'sha256-");
    const html = await callback.text();
    expect(html).toContain(`<form method="post" action="${APP}">`);
    const fields = hiddenFields(html);
    expect(fields.state).toBe(checks.expectedState);
    expect(fields.iss).toBe(ISSUER);
    expect(fields.code).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const posted = new Request(APP, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(fields).toString() });
    const tokens = await oidc.authorizationCodeGrant(config, posted, checks);
    expect(tokens.claims().sub).toBe(JOHN);
  });
});

// ---------------------------------------------------------------- client authentication --

describe('client authentication and PKCE', () => {
  it('client_secret_post works', async () => {
    const { tokens } = await fullSignIn({ method: 'post' });
    expect(tokens.claims().sub).toBe(JOHN);
  });

  it('an app without a secret signs in with PKCE', async () => {
    const { creds, tokens } = await fullSignIn({ method: 'none', redirectUri: 'https://cli.example.com/cb' });
    expect(creds.clientSecret).toBeNull();
    expect(tokens.claims().aud).toBe(creds.clientId);
  });

  it('an app without a secret must send a PKCE challenge', async () => {
    const creds = await createCredentials(DOMAIN, 'https://cli.example.com/cb', { secret: false });
    const res = await req(makeJar(), 'GET', `/${DOMAIN}/authorize?response_type=code&client_id=${creds.clientId}&redirect_uri=${encodeURIComponent('https://cli.example.com/cb')}&state=s`);
    expect(res.status).toBe(400);
    const html = await res.text();
    expect(html).toContain('must use PKCE');
    expect(html).toContain('Return to cli.example.com');
  });

  it('a wrong secret is invalid_client, with a Basic challenge when Basic was used', async () => {
    const { creds, checks, code } = await obtainCode();
    const wrong = creds.clientSecret.slice(0, 42) + (creds.clientSecret.endsWith('A') ? 'B' : 'A');
    const res = await tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: APP }, { basic: { id: creds.clientId, secret: wrong } });
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toContain('Basic');
    expect((await res.json()).error).toBe('invalid_client');
    // The code survived the failed attempt and still works with the right secret.
    const ok = await tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: APP, code_verifier: checks.pkceCodeVerifier }, { basic: { id: creds.clientId, secret: creds.clientSecret } });
    expect(ok.status).toBe(200);
  });

  it('a wrong PKCE verifier, or a verifier without a challenge, is invalid_grant', async () => {
    const mismatch = await obtainCode();
    const res = await tokenRequest({ grant_type: 'authorization_code', code: mismatch.code, redirect_uri: APP, code_verifier: oidc.randomPKCECodeVerifier() },
      { basic: { id: mismatch.creds.clientId, secret: mismatch.creds.clientSecret } });
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe('invalid_grant');

    // No challenge in the request (a confidential app that skips PKCE), then a verifier at /token.
    const creds = await createCredentials(DOMAIN, APP);
    const config = await discover(ISSUER, creds.clientId, { secret: creds.clientSecret });
    const url = oidc.buildAuthorizationUrl(config, { redirect_uri: APP, scope: 'openid', state: oidc.randomState() });
    const { callback } = await browserSignIn(makeJar(), url);
    const code = new URL(callback.headers.get('location')).searchParams.get('code');
    const downgrade = await tokenRequest({ grant_type: 'authorization_code', code, redirect_uri: APP, code_verifier: oidc.randomPKCECodeVerifier() },
      { basic: { id: creds.clientId, secret: creds.clientSecret } });
    expect((await downgrade.json()).error).toBe('invalid_grant');
  });

  it('other grant types, bad bodies, and bad tokens at /userinfo are refused', async () => {
    const creds = await createCredentials(DOMAIN, APP);
    const grant = await tokenRequest({ grant_type: 'refresh_token', refresh_token: 'x' }, { basic: { id: creds.clientId, secret: creds.clientSecret } });
    expect(grant.status).toBe(400);
    expect((await grant.json()).error).toBe('unsupported_grant_type');
    expect((await tokenRequest({ grant_type: 'authorization_code', code: 'x', redirect_uri: APP })).status).toBe(400);

    const noToken = await req(makeJar(), 'GET', `/${DOMAIN}/userinfo`);
    expect(noToken.status).toBe(401);
    expect(noToken.headers.get('www-authenticate')).toContain('Bearer');
    expect((await req(makeJar(), 'POST', `/${DOMAIN}/userinfo`, { form: { other: 'x' } })).status).toBe(401);
    const garbage = await req(makeJar(), 'GET', `/${DOMAIN}/userinfo`, { headers: { Authorization: 'Bearer abc.def.ghi' } });
    expect(garbage.status).toBe(401);
    expect((await garbage.json()).error).toBe('invalid_token');

    const { tokens } = await fullSignIn();
    const idTokenAsAccess = await req(makeJar(), 'GET', `/${DOMAIN}/userinfo`, { headers: { Authorization: `Bearer ${tokens.id_token}` } });
    expect(idTokenAsAccess.status).toBe(401);
    const otherDomain = await req(makeJar(), 'GET', '/other.example/userinfo', { headers: { Authorization: `Bearer ${tokens.access_token}` } });
    expect(otherDomain.status).toBe(401);
  });
});

// ------------------------------------------------------------------------------ options --

describe("a client ID's options", () => {
  it('an app limited to a group lets its members in', async () => {
    // john is in admins and dev (global-setup.mjs).
    const { creds, tokens } = await fullSignIn({ group: 'admins' });
    expect(creds.clientId).toMatch(/^[a-z2-7]{26}_[a-z2-7]{26}_g-admins$/);
    const claims = tokens.claims();
    expect(claims.sub).toBe(JOHN);
    expect(claims.aud).toBe(creds.clientId);
    expect(claims.groups).toContain('admins@triauthdemo.org');
  });

  it('an app limited to a group refuses everyone else after the sign-in, before any code exists', async () => {
    const { url } = await prepare({ group: 'billing' });
    const before = new Set((await storedRecords()).map(([name]) => name));
    const { callback } = await browserSignIn(makeJar(), url);
    expect(callback.status).toBe(403);
    expect(callback.headers.get('location')).toBeNull();
    const html = await callback.text();
    expect(html).toContain('Only members of billing@triauthdemo.org can sign in to this app.');
    expect(html).toContain('value="john"');
    expect((await storedRecords()).filter(([name]) => !before.has(name))).toHaveLength(0);
  });

  it('nobody can remove or change the limit: the client ID no longer checks out', async () => {
    const creds = await createCredentials(DOMAIN, APP, { group: 'billing' });
    for (const clientId of [creds.clientId.replace('_g-billing', ''), creds.clientId.replace('_g-billing', '_g-admins')]) {
      const res = await req(makeJar(), 'GET', `/${DOMAIN}/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(APP)}&state=s`);
      expect(res.status).toBe(400);
      expect(await res.text()).toContain('was not made for');
    }
  });
});

// -------------------------------------------------------------------------------- users --

describe('what users meet', () => {
  it('two sign-ins in two tabs of one browser both complete', async () => {
    const first = await prepare();
    const second = await prepare({ redirectUri: 'https://wiki.example.com/oidc/callback' });
    const jar = makeJar();

    const start = async ({ url }, host) => {
      const fields = hiddenFields(await (await req(jar, 'GET', url.toString())).text());
      const login = await req(jar, 'POST', `/${DOMAIN}/login`, { headers: { Origin: BASE }, form: { ...fields, username: 'john' } });
      return { challenge: challengeFrom(login.headers.get('location')), host };
    };
    const a = await start(first, APP_HOST);
    const b = await start(second, 'wiki.example.com');
    expect([...jar.cookies.keys()].filter((k) => k.startsWith('__Host-triauth_f_'))).toHaveLength(2);

    const finish = async ({ challenge, host }) => req(jar, 'POST', callbackUrlOf(challenge), { form: { response: await approve(challenge, { identifier: JOHN, keys: JOHN_LAPTOP, host }) } });
    const doneB = await finish(b);
    const doneA = await finish(a);
    expect(doneA.status).toBe(302);
    expect(doneB.status).toBe(302);
    expect(new URL(doneA.headers.get('location')).origin).toBe('https://grafana.example.com');
    expect(new URL(doneB.headers.get('location')).origin).toBe('https://wiki.example.com');
    const tokensA = await oidc.authorizationCodeGrant(first.config, new URL(doneA.headers.get('location')), first.checks);
    const tokensB = await oidc.authorizationCodeGrant(second.config, new URL(doneB.headers.get('location')), second.checks);
    expect(tokensA.claims().sub).toBe(JOHN);
    expect(tokensB.claims().sub).toBe(JOHN);
  });

  it('the username field forgives capitals and the domain, and refuses other domains', async () => {
    const { url } = await prepare();
    const { callback } = await browserSignIn(makeJar(), url, { username: 'John@TriauthDemo.org' });
    expect(callback.status).toBe(302);

    const jar = makeJar();
    const fields = hiddenFields(await (await req(jar, 'GET', url.toString())).text());
    const wrongDomain = await req(jar, 'POST', `/${DOMAIN}/login`, { headers: { Origin: BASE }, form: { ...fields, username: 'john@other.com' } });
    expect(wrongDomain.status).toBe(400);
    expect(await wrongDomain.text()).toContain(`Type only the part before @${DOMAIN}.`);
    const crossSite = await req(jar, 'POST', `/${DOMAIN}/login`, { headers: { Origin: 'https://evil.test' }, form: { ...fields, username: 'john' } });
    expect(crossSite.status).toBe(403);
  });

  it('a response for an unknown identity, or a delegated one, shows the sign-in page with the reason', async () => {
    const { url } = await prepare();
    const unknown = await browserSignIn(makeJar(), url, { username: 'nobody', identifier: 'nobody@triauthdemo.org' });
    expect(unknown.callback.status).toBe(400);
    expect(await unknown.callback.text()).toContain('could not be verified');

    const delegated = await browserSignIn(makeJar(), url, { username: 'jane', identifier: 'jane@triauthdemo.org', actor: JOHN });
    expect(delegated.callback.status).toBe(400);
    const html = await delegated.callback.text();
    expect(html).toContain('Delegated sign-ins');
    expect(html).toContain('value="jane"');
  });

  it('a domain without a triauth record fails at stage 1 with a clear message', async () => {
    const creds = await createCredentials('unconfigured.example', 'https://app.unconfigured.example/cb');
    const jar = makeJar();
    const page = await req(jar, 'GET', `/unconfigured.example/authorize?response_type=code&client_id=${creds.clientId}&redirect_uri=${encodeURIComponent('https://app.unconfigured.example/cb')}`);
    expect(page.status).toBe(200);
    const login = await req(jar, 'POST', '/unconfigured.example/login', { headers: { Origin: BASE }, form: { ...hiddenFields(await page.text()), username: 'john' } });
    expect(login.status).toBe(400);
    expect(await login.text()).toContain('no triauth DNS record');
  });

  it("the authenticator's tile is named after the app's host", async () => {
    const { url } = await prepare();
    const { challenge } = await browserSignIn(makeJar(), url);
    expect(manifestOf(challenge)).toEqual({ name: APP_HOST });
  });

  it('login_hint and the remembered username prefill the field', async () => {
    const creds = await createCredentials(DOMAIN, APP);
    const base = `/${DOMAIN}/authorize?response_type=code&client_id=${creds.clientId}&redirect_uri=${encodeURIComponent(APP)}`;
    expect(await (await req(makeJar(), 'GET', `${base}&login_hint=John`)).text()).toContain('value="john"');
    expect(await (await req(makeJar(), 'GET', `${base}&login_hint=john%40other.com`)).text()).toContain('value=""');

    const { jar } = await fullSignIn();
    expect(jar.cookies.get('__Host-triauth_user')).toBe(JOHN);
    expect(await (await req(jar, 'GET', base)).text()).toContain('value="john"');
    const other = await createCredentials('other.example', 'https://app.other.example/cb');
    expect(await (await req(jar, 'GET', `/other.example/authorize?response_type=code&client_id=${other.clientId}&redirect_uri=${encodeURIComponent('https://app.other.example/cb')}`)).text()).toContain('value=""');
  });

  it('the rate limits answer 429 to a flood from one address, per kind of endpoint', async () => {
    const jar = makeJar();
    let last;
    for (let i = 0; i < 21; i++) {
      last = await req(jar, 'POST', `/${DOMAIN}/login`, { headers: { Origin: BASE }, form: { username: 'john' } });
    }
    expect(last.status).toBe(429);
    expect(last.headers.get('retry-after')).toBe('60');
    // The same address may still call /token: the limits are separate.
    const creds = await createCredentials(DOMAIN, APP);
    for (let i = 0; i < 61; i++) {
      last = await req(jar, 'POST', `/${DOMAIN}/token`, { form: { grant_type: 'authorization_code', code: 'x', redirect_uri: APP, client_id: creds.clientId, client_secret: creds.clientSecret } });
    }
    expect(last.status).toBe(429);
    expect(last.headers.get('retry-after')).toBe('60');
    expect((await last.json()).error).toBe('temporarily_unavailable');
  });

  it('plain http is sent to https and never served; every response carries HSTS', async () => {
    const http = await req(makeJar(), 'GET', `/${DOMAIN}/jwks`, { headers: { 'CF-Visitor': '{"scheme":"http"}' } });
    expect(http.status).toBe(301);
    expect(http.headers.get('location')).toBe(`${BASE}/${DOMAIN}/jwks`);
    const post = await req(makeJar(), 'POST', `/${DOMAIN}/token`, { headers: { 'CF-Visitor': '{"scheme":"http"}' }, form: { grant_type: 'x' } });
    expect(post.status).toBe(400);
    const https = await req(makeJar(), 'GET', `/${DOMAIN}/jwks`, { headers: { 'CF-Visitor': '{"scheme":"https"}' } });
    expect(https.status).toBe(200);
    expect(https.headers.get('strict-transport-security')).toBe('max-age=31536000');
    expect((await req(makeJar(), 'GET', '/')).headers.get('strict-transport-security')).toBe('max-age=31536000');
  });

  it('a malformed redirect_uri at /token, a bridge-host redirect URI, and an oversized body are refused cleanly', async () => {
    const creds = await createCredentials(DOMAIN, APP);
    const malformed = await tokenRequest({ grant_type: 'authorization_code', code: 'x', redirect_uri: 'foo' }, { basic: { id: creds.clientId, secret: creds.clientSecret } });
    expect(malformed.status).toBe(400);
    expect(malformed.headers.get('content-type')).toContain('application/json');
    expect((await malformed.json()).error).toBe('invalid_request');

    const port = await req(makeJar(), 'POST', `/${DOMAIN}/credentials`, { headers: { Origin: BASE }, form: { redirect_uri: 'https://oidc.test:8443/x' } });
    expect(port.status).toBe(400);
    expect(await port.text()).toContain('own host');

    const big = await req(makeJar(), 'POST', `/${DOMAIN}/login`, { headers: { Origin: BASE }, form: { username: 'x'.repeat(70000) } });
    expect(big.status).toBe(400);
    expect(await big.text()).toContain('could not be read');
  });

  it("an internal error answers in the endpoint's format: JSON with CORS for apps, a page for people", async () => {
    const broken = { ...env, STORE: undefined };   // the first storage access throws
    const formHeaders = { 'Content-Type': 'application/x-www-form-urlencoded' };
    const creds = await createCredentials(DOMAIN, APP);
    const body = new URLSearchParams({ grant_type: 'authorization_code', code: 'A'.repeat(43), redirect_uri: APP, client_id: creds.clientId, client_secret: creds.clientSecret }).toString();
    const api = await worker.fetch(new Request(`${BASE}/${DOMAIN}/token`, { method: 'POST', headers: { ...formHeaders, 'CF-Connecting-IP': '10.97.0.1' }, body }), broken);
    expect(api.status).toBe(500);
    expect(api.headers.get('content-type')).toContain('application/json');
    expect(api.headers.get('access-control-allow-origin')).toBe('*');
    expect(api.headers.get('strict-transport-security')).toBe('max-age=31536000');
    expect((await api.json()).error).toBe('server_error');

    const flowId = 'a'.repeat(16);
    const page = await worker.fetch(new Request(`${BASE}/${DOMAIN}/apps/${APP_HOST}/callback?f=${flowId}`, {
      method: 'POST', headers: { ...formHeaders, 'CF-Connecting-IP': '10.97.0.2', Cookie: `__Host-triauth_f_${flowId}=${'A'.repeat(43)}` }, body: 'response=x',
    }), broken);
    expect(page.status).toBe(500);
    expect(page.headers.get('content-type')).toContain('text/html');
    expect(await page.text()).toContain('Something went wrong');
  });
});
