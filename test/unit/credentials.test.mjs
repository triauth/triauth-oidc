// The client ID and secret recipe (src/lib/credentials.js): fixed vectors, parsing of hostile input,
// the options, the redirect URI rules, and the checks the endpoints rely on.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCredentials, credentialsFor, parseClientId, checkClient, checkSecret, refusalFor, isGroupName, groupNameProblem, redirectUriProblem, publicClientProblem, sameRedirectUri, appHost, appRootUrl, newSecret, SECRET_LENGTH } from '../../src/lib/credentials.js';

const BRIDGE = 'oidc.triauth.org';
const URI = 'https://grafana.example.com/login/generic_oauth';
const ZERO_SECRET = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';   // 32 zero bytes

test('a client ID is r, then s, then the options, joined by _', async () => {
  const c = await createCredentials('example.com', URI);
  assert.match(c.clientId, /^[a-z2-7]{26}_[a-z2-7]{26}$/);
  assert.equal(c.clientSecret.length, SECRET_LENGTH);
  assert.match(c.clientSecret, /^[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(c.hosts, ['grafana.example.com']);
  assert.deepEqual(c.redirectUris, [URI]);
  assert.equal(c.group, null);

  const limited = await createCredentials('example.com', URI, { group: 'admins' });
  assert.match(limited.clientId, /^[a-z2-7]{26}_[a-z2-7]{26}_g-admins$/);
  assert.equal(limited.group, 'admins');
  assert.match((await createCredentials('example.com', URI, { secret: false, group: 'dev-ops' })).clientId, /^[a-z2-7]{26}_g-dev-ops$/);
});

test('the recipe is deterministic for a given domain, redirect URI, secret and options (fixed vectors)', async () => {
  // If these vectors change, every issued client ID stops working.
  const c = await credentialsFor('example.com', URI, ZERO_SECRET);
  assert.equal(c.clientId, '6n5277rpe64dgikdr5bkceiuqq_aszpe4odoc3swcioqdufcsdkue');
  assert.equal((await credentialsFor('example.com', 'https://wiki.example.com/oidc/callback', null)).clientId, 'hkuazvlwsw6e6nkr5jefovgpjl');
  assert.equal((await credentialsFor('example.com', 'https://acme.cloudflareaccess.com/cdn-cgi/access/callback', ZERO_SECRET)).clientId,
    'm4hq2dlgrhravwoyemltbcbv7w_aszpe4odoc3swcioqdufcsdkue');
  assert.equal((await credentialsFor('example.com', 'https://pve.example.com:8006', ZERO_SECRET)).clientId,
    'vy7337q3knevvgu76nn6jfkznw_aszpe4odoc3swcioqdufcsdkue');
  const limited = await credentialsFor('example.com', URI, ZERO_SECRET, { group: 'admins' });
  assert.equal(limited.clientId, 'shdfgeiglavch24meoi3ez37ve_aszpe4odoc3swcioqdufcsdkue_g-admins');
  assert.equal((await credentialsFor('example.com', URI, null, { group: 'admins' })).clientId, 'gzvl2be2a6usxd7xf7622srh2q_g-admins');

  // The same values, recomputed here independently of credentials.js: r covers everything after it.
  const client = parseClientId(c.clientId);
  assert.equal(client.s, await fingerprintOf('triauth-oidc/v1/secret', [ZERO_SECRET]));
  assert.deepEqual(client.r, [await fingerprintOf('triauth-oidc/v1/client', ['example.com', URI, client.s])]);
  assert.deepEqual(parseClientId(limited.clientId).r, [await fingerprintOf('triauth-oidc/v1/client', ['example.com', URI, `${client.s}_g-admins`])]);
});

test('a client ID without a secret is r alone, or r and its options', async () => {
  const c = await createCredentials('example.com', 'http://localhost:3000/cb', { secret: false });
  assert.equal(c.clientSecret, null);
  assert.match(c.clientId, /^[a-z2-7]{26}$/);
  assert.deepEqual(c.hosts, ['localhost:3000']);
  assert.deepEqual(parseClientId(c.clientId), { r: [c.clientId], s: '', rest: '', confidential: false, group: null });
  const limited = parseClientId('gzvl2be2a6usxd7xf7622srh2q_g-admins');
  assert.deepEqual(limited, { r: ['gzvl2be2a6usxd7xf7622srh2q'], s: '', rest: 'g-admins', confidential: false, group: 'admins' });
});

test('an app with several redirect URIs has one r per URI, sorted and joined by ".", and signs in through any of them', async () => {
  // Immich: its web login, its account-linking page, and its own https stand-in for the mobile app's callback.
  const LOGIN = 'https://photos.example.com/auth/login';
  const SETTINGS = 'https://photos.example.com/user-settings';
  const MOBILE = 'https://photos.example.com/api/oauth/mobile-redirect';
  const c = await credentialsFor('example.com', [LOGIN, SETTINGS, MOBILE], ZERO_SECRET, { group: 'family' });
  assert.equal(c.clientId, 'f4j3hbifvnjppzttfvtjzqbzus.oa3v6ryyzcfylhslrlpjqdx5db.orxvgvbiu7qq35pat57vxptmmc_aszpe4odoc3swcioqdufcsdkue_g-family');
  assert.deepEqual(c.redirectUris, [LOGIN, SETTINGS, MOBILE]);
  assert.deepEqual(c.hosts, ['photos.example.com']);
  assert.equal((await credentialsFor('example.com', [MOBILE, LOGIN, SETTINGS], ZERO_SECRET, { group: 'family' })).clientId, c.clientId, 'in any order');
  const client = parseClientId(c.clientId);
  assert.equal(client.rest, 'aszpe4odoc3swcioqdufcsdkue_g-family');
  for (const uri of [LOGIN, SETTINGS, MOBILE]) {
    // Each r is the r of that URI alone, with the same secret and options, so each covers the rest.
    const alone = await credentialsFor('example.com', uri, ZERO_SECRET, { group: 'family' });
    assert.ok(client.r.includes(parseClientId(alone.clientId).r[0]), uri);
    assert.equal(parseClientId(alone.clientId).r[0], await fingerprintOf('triauth-oidc/v1/client', ['example.com', uri, client.rest]));
    assert.equal((await checkClient('example.com', c.clientId, uri))?.host, 'photos.example.com', uri);
  }
  assert.deepEqual(client.r, [...client.r].sort());
  assert.equal(await checkClient('example.com', c.clientId, 'https://photos.example.com/auth/login/'), null);
  assert.equal(await checkClient('example.com', c.clientId, 'https://photos.example.com/'), null);
  assert.equal(await checkClient('other.com', c.clientId, LOGIN), null);
  assert.equal(await checkClient('example.com', c.clientId.replace('_g-family', ''), LOGIN), null, 'every r covers the options');

  // The hosts, each once; two spellings of one URL count once; one to three URIs.
  const vault = await credentialsFor('example.com', ['https://vault.example.com/ui/vault/auth/oidc/oidc/callback', 'http://localhost:8250/oidc/callback'], ZERO_SECRET);
  assert.equal(vault.clientId, '2yaztzoglp62kd6ujs7cq3iuit.k3fhws647jfexwhcg4ja56w323_aszpe4odoc3swcioqdufcsdkue');
  assert.deepEqual(vault.hosts, ['vault.example.com', 'localhost:8250']);
  const once = await credentialsFor('example.com', ['https://pve.example.com:8006', 'https://pve.example.com:8006/'], ZERO_SECRET);
  assert.equal(once.clientId, (await credentialsFor('example.com', 'https://pve.example.com:8006', ZERO_SECRET)).clientId);
  assert.deepEqual(once.redirectUris, ['https://pve.example.com:8006']);
  await assert.rejects(credentialsFor('example.com', [], ZERO_SECRET), TypeError);
  await assert.rejects(credentialsFor('example.com', [LOGIN, SETTINGS, MOBILE, 'https://photos.example.com/x'], ZERO_SECRET), TypeError);
});

test('checkClient accepts the exact domain, redirect URI and options only', async () => {
  const c = await createCredentials('example.com', URI, { group: 'admins' });
  const client = await checkClient('example.com', c.clientId, URI);
  assert.equal(client.host, 'grafana.example.com');
  assert.equal(client.group, 'admins');
  assert.equal(await checkClient('example.com', c.clientId, 'https://grafana.example.com/login/other'), null);
  assert.equal(await checkClient('example.com', c.clientId, 'https://grafana.example.com/login/generic_oauth?x=1'), null);
  assert.equal(await checkClient('other.com', c.clientId, URI), null);
  assert.equal(await checkClient('example.com', c.clientId, 'foo'), null, 'a non-URL is a mismatch, not an exception');
  assert.equal(await checkClient('example.com', c.clientId, ''), null);
  assert.equal(await checkClient('example.com', c.clientId, undefined), null);
  assert.equal(await checkClient('example.com', c.clientId.replace(/^./, (ch) => ch === 'a' ? 'b' : 'a'), URI), null);
  // The options cannot be removed, changed, or added: r covers them.
  assert.equal(await checkClient('example.com', c.clientId.replace('_g-admins', ''), URI), null);
  assert.equal(await checkClient('example.com', c.clientId.replace('_g-admins', '_g-dev'), URI), null);
  const open = await createCredentials('example.com', URI);
  assert.ok(await checkClient('example.com', open.clientId, URI));
  assert.equal(await checkClient('example.com', `${open.clientId}_g-admins`, URI), null);
});

test('checkSecret needs the exact 43-character secret of a confidential client', async () => {
  const c = await createCredentials('example.com', URI);
  const client = await checkClient('example.com', c.clientId, URI);
  assert.equal(await checkSecret(client, c.clientSecret), true);
  assert.equal(await checkSecret(client, c.clientSecret.slice(0, 42) + (c.clientSecret.endsWith('A') ? 'B' : 'A')), false);
  assert.equal(await checkSecret(client, c.clientSecret + 'A'), false);
  assert.equal(await checkSecret(client, ''), false);
  assert.equal(await checkSecret(client, null), false);
  const pub = await checkClient('example.com', (await createCredentials('example.com', URI, { secret: false })).clientId, URI);
  assert.equal(await checkSecret(pub, newSecret()), false, 'a public client has no secret to check');
});

test('parseClientId refuses hostile and malformed input, and any second spelling of the options', () => {
  const r = 'a'.repeat(26), s = 'b'.repeat(26), c = 'c'.repeat(26);
  assert.ok(parseClientId(`${r}_${s}_g-admins`));
  assert.ok(parseClientId(`${r}.${s}.${c}_${s}_g-admins`));
  for (const bad of [undefined, null, 42, '', r.slice(1), r.toUpperCase(), `${r}_`, `_${r}`, `${r}__${s}`, `${r}_${s}_`, `${r}~${s}`,
    `${s}.${r}_${s}`, `${r}.${r}_${s}`, `${r}.${s}.${s}_${s}`, `${r}.${s}.${c}.${'d'.repeat(26)}_${s}`, `${r}._${s}`, `.${r}_${s}`, `${r}.${s.slice(1)}_${s}`, `${r}.${s}.`,
    `grafana.example.com~${s}~${r}`, `${r}_${s}_${s}`, `${r}_${s}_g-`, `${r}_${s}_g`, `${r}_${s}_x-1`, `${r}_${s}_g-admins_g-dev`,
    `${r}_${s}_g-Admins`, `${r}_${s}_g--admins`, `${r}_${s}_g-admins-`, `${r}_${s}_g-a.b`, `${r}_${s}_g-${'a'.repeat(21)}`,
    `${r}_g-admins_${s}`, `${r}_${s}_g-admins\n`, `${r}_${s}_gadmins`, 'x'.repeat(600)]) {
    assert.equal(parseClientId(bad), null, JSON.stringify(bad));
  }
});

test('refusalFor lets in the members of the group, or everyone when there is none', () => {
  const claims = (...groups) => ({ groups });
  assert.equal(refusalFor({ group: null }, claims(), 'example.com'), null);
  assert.equal(refusalFor({ group: 'admins' }, claims('admins@example.com', 'dev@example.com'), 'example.com'), null);
  assert.equal(refusalFor({ group: 'admins' }, claims('dev@example.com'), 'example.com'), 'Only members of admins@example.com can sign in to this app.');
  assert.notEqual(refusalFor({ group: 'admins' }, claims(), 'example.com'), null);
  assert.notEqual(refusalFor({ group: 'admins' }, claims('admins@other.com'), 'example.com'), null, 'a group at another domain is another group');
});

test('group names follow triauth, and the recipe refuses any other', async () => {
  for (const good of ['admins', 'project-x', 'a-b-c', 'a'.repeat(20)]) {
    assert.equal(isGroupName(good), true, good);
  }
  for (const bad of ['', 'Admins', '-x', 'x-', 'a--b', 'a_b', 'a.b', 'admins@example.com', 'a'.repeat(21), null, undefined, 42]) {
    assert.equal(isGroupName(bad), false, JSON.stringify(bad));
  }
  await assert.rejects(credentialsFor('example.com', URI, null, { group: 'Admins' }), TypeError);
  assert.equal(groupNameProblem('admins', 'example.com'), null);
  assert.match(groupNameProblem('', 'example.com'), /^Type the name of the group/);
  assert.match(groupNameProblem('a'.repeat(21), 'example.com'), /at most 20 characters/);
  assert.match(groupNameProblem('a--b', 'example.com'), /single hyphens.*before @example\.com\./);
  assert.match(groupNameProblem('Admins', 'example.com'), /lowercase letters/);
});

test('redirect URIs must be canonical https (or http on a loopback host), without fragment, off the bridge host', () => {
  for (const good of [URI, 'http://localhost:3000/callback', 'https://app.example.com/cb?x=1', 'https://192.168.0.254:8006/',
    'https://192.168.0.254:8006', 'https://pve.example.com:8006', 'https://app.example.com?x=1', 'http://localhost:8000',
    'http://127.0.0.1:6274/cb', 'http://127.0.0.1/cb']) {
    assert.equal(redirectUriProblem(good, BRIDGE), null, good);
  }
  for (const bad of ['', undefined, 'http://grafana.example.com/x', 'https://Grafana.example.com/x', 'http://192.168.0.254:8006/',
    'http://127.0.0.2/x', 'http://[::1]:3000/x', 'http://localhost.example.com/x',
    'https://1.2.3/x', 'https://01.2.3.4/x', 'https://3232235774/x', 'https://grafana.example.com#frag', 'https://',
    'https://[::1]/x', 'https://user@grafana.example.com/x', 'https://grafana.example.com/x#frag', 'https://grafana.example.com/a/../x',
    'https://xn--80ak6aa92e.com/x', 'javascript:alert(1)', `https://${BRIDGE}/example.com/authorize`, 'https://grafana.example.com:443/x',
    'https://grafana.example.com/x y', `https://${BRIDGE}:8443/x`, `https://apps.${BRIDGE}/x`]) {
    assert.notEqual(redirectUriProblem(bad, BRIDGE), null, JSON.stringify(bad));
  }
});

test('an app without a secret needs a domain name or a loopback host in its redirect URI', () => {
  for (const good of [URI, 'https://pve.lan:8006/', 'https://pve.example.com:8006', 'http://localhost:8000', 'https://localhost/cb', 'http://127.0.0.1:6274/cb']) {
    assert.equal(publicClientProblem(good), null, good);
  }
  for (const bad of ['https://192.168.0.254:8006/', 'https://192.168.0.254:8006', 'https://203.0.113.5/cb', 'https://proxmox:8006/']) {
    assert.match(publicClientProblem(bad), /needs a domain name in its redirect URI/, bad);
  }
});

test('a redirect URI without a path is the same URL as with "/": one client ID, either spelling', async () => {
  const bare = await credentialsFor('example.com', 'https://pve.example.com:8006', ZERO_SECRET);
  assert.equal(bare.clientId, (await credentialsFor('example.com', 'https://pve.example.com:8006/', ZERO_SECRET)).clientId);
  assert.deepEqual(bare.redirectUris, ['https://pve.example.com:8006']);
  const client = parseClientId(bare.clientId);
  assert.deepEqual(client.r, [await fingerprintOf('triauth-oidc/v1/client', ['example.com', 'https://pve.example.com:8006/', client.s])]);
  assert.ok(await checkClient('example.com', bare.clientId, 'https://pve.example.com:8006/'));
  assert.ok(await checkClient('example.com', bare.clientId, 'https://pve.example.com:8006'));
  assert.ok(sameRedirectUri('https://pve.example.com:8006', 'https://pve.example.com:8006/'));
  assert.ok(sameRedirectUri('https://app.example.com?x=1', 'https://app.example.com/?x=1'));

  // Only an empty path: with a path, a trailing slash makes another URL.
  assert.ok(!sameRedirectUri('https://app.example.com/cb', 'https://app.example.com/cb/'));
  const cb = await credentialsFor('example.com', 'https://app.example.com/cb', null);
  assert.equal(await checkClient('example.com', cb.clientId, 'https://app.example.com/cb/'), null);
});

test('appHost keeps a non-default port, and is null for a non-URL', () => {
  assert.equal(appHost(URI), 'grafana.example.com');
  assert.equal(appHost('foo'), null);
  assert.equal(appHost(''), null);
  assert.equal(appHost('https://app.example.com:8443/cb'), 'app.example.com:8443');
  assert.equal(appHost('http://localhost:3000/cb'), 'localhost:3000');
});

// -- helpers that recompute the recipe independently of credentials.js --

async function fingerprintOf(label, parts) {
  const bytes = [...new TextEncoder().encode(label)];
  for (const part of parts) {
    bytes.push(0, ...new TextEncoder().encode(part));
  }
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(bytes)));
  return base32(digest).slice(0, 26);
}

function base32(bytes) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  let bits = 0, value = 0, out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += alphabet[(value << (5 - bits)) & 31];
  }
  return out;
}

test('appRootUrl is the root of the host, http for a loopback host, and null for a host no redirect URI could have', () => {
  assert.equal(appRootUrl('app.example.com', 'oidc.test'), 'https://app.example.com/');
  assert.equal(appRootUrl('app.example.com:8443', 'oidc.test'), 'https://app.example.com:8443/');
  assert.equal(appRootUrl('192.168.0.14:8006', 'oidc.test'), 'https://192.168.0.14:8006/');
  assert.equal(appRootUrl('localhost', 'oidc.test'), 'http://localhost/');
  assert.equal(appRootUrl('127.0.0.1:6274', 'oidc.test'), 'http://127.0.0.1:6274/');
  assert.equal(appRootUrl('localhost:3000', 'oidc.test'), 'http://localhost:3000/');
  for (const host of ['oidc.test', 'oidc.test:8443', 'x.oidc.test', 'a..b', '-a.b', 'app.example.com:443', 'localhost:80', 'xn--80ak6aa92e.com']) {
    assert.equal(appRootUrl(host, 'oidc.test'), null, host);
  }
});
