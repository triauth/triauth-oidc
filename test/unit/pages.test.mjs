// The HTML tag (src/lib/html.js) and the pages (src/lib/pages.js): escaping in one place, headers,
// and the shape of each page as a Response.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { html, raw, escape, pageHeaders } from '../../src/lib/html.js';
import { signInPage, errorPage, domainPage, credentialsPage, formPostPage, tilePage, homePage } from '../../src/lib/pages.js';
import { FORM_POST_SCRIPT, FORM_POST_SCRIPT_HASH } from '../../src/views/form-post.js';
import { providerFor } from '../../src/lib/provider.js';
import { version, sourceUrl } from '../../src/build-info.js';

const provider = providerFor('https://oidc.test', 'example.com');
const HOSTILE = `"><img src=x onerror=alert(1)><script>alert('x')</script>&`;

test('the html tag escapes every interpolation unless marked raw', () => {
  const out = html`<p title="${HOSTILE}">${HOSTILE}${raw('<b>ok</b>')}${['<a>', raw('<i>')]}${null}${undefined}${false}${0}</p>`.toString();
  assert.equal(out.includes('<img'), false);
  assert.equal(out.includes('<script'), false);
  assert.ok(out.includes('&lt;script&gt;'));
  assert.ok(out.includes('&quot;&gt;&lt;img'));
  assert.ok(out.includes('<b>ok</b>&lt;a&gt;<i>'));
  assert.ok(out.endsWith('0</p>'));
  assert.equal(escape(`<>&"'`), '&lt;&gt;&amp;&quot;&#39;');
});

test('every page carries the security headers, and only form_post allows its one script', async () => {
  const strict = pageHeaders();
  assert.match(strict['Content-Security-Policy'], /default-src 'none'/);
  assert.match(strict['Content-Security-Policy'], /script-src 'none'/);
  assert.match(strict['Content-Security-Policy'], /frame-ancestors 'none'/);
  assert.equal(strict['Content-Security-Policy'].includes('form-action'), false, 'form-action would break the redirect to the authenticator');
  assert.equal(strict['Referrer-Policy'], 'strict-origin-when-cross-origin');
  assert.equal(strict['X-Frame-Options'], 'DENY');
  assert.equal(strict['Cache-Control'], 'no-store');

  const hash = Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(FORM_POST_SCRIPT))).toString('base64');
  assert.equal(FORM_POST_SCRIPT_HASH, `sha256-${hash}`);
  const res = formPostPage({ action: 'https://app.example.com/cb', fields: { code: 'c', state: 's', iss: provider.issuer, nonce: undefined }, host: 'app.example.com' });
  assert.match(res.headers.get('Content-Security-Policy'), new RegExp(`script-src '${FORM_POST_SCRIPT_HASH.replace(/[+/]/g, '\\$&')}'`));
  const body = await res.text();
  assert.ok(body.includes('<form method="post" action="https://app.example.com/cb">'));
  assert.ok(body.includes('name="code" value="c"'));
  assert.equal(body.includes('nonce'), false);
  assert.ok(body.includes(`<script>${FORM_POST_SCRIPT}</script>`));
});

test('the sign-in page names the app and carries the request as hidden fields, escaped', async () => {
  const request = { client_id: 'r_s', redirect_uri: 'https://app.example.com/cb', scope: 'openid', state: HOSTILE, nonce: undefined, code_challenge: undefined, response_mode: 'query' };
  const res = signInPage({ provider, request, host: 'app.example.com', username: HOSTILE, error: HOSTILE });
  assert.equal(res.status, 200);
  const body = await res.text();
  assert.ok(body.includes('Sign in to <span class="mark" title="https://app.example.com/cb">app.<wbr>example.<wbr>com</span>'));
  assert.ok(body.includes(`action="${provider.login}"`));
  assert.ok(body.includes('name="state"'));
  assert.equal(body.includes('nonce'), false);
  assert.equal(body.includes('<img'), false);
  assert.equal(body.includes('<script'), false);
  assert.ok(body.includes('@example.com</span>'));
  assert.ok(body.includes('By continuing, you agree to the triauth <a href="https://www.triauth.org/legal/terms"'), 'the notice links the Terms');
});

test('the error page links back only when asked, and never redirects', async () => {
  const plain = errorPage({ title: 'T', text: HOSTILE });
  assert.equal(plain.status, 400);
  assert.equal(plain.headers.get('Location'), null);
  assert.equal((await plain.text()).includes('class="button"'), false);
  const back = errorPage({ title: 'T', text: 'x', returnTo: { url: 'https://app.example.com/cb?error=e', host: 'app.example.com' }, status: 400 });
  const body = await back.text();
  assert.ok(body.includes('<a class="button" href="https://app.example.com/cb?error=e">Return to app.example.com</a>'));

  // For a form_post app, the way back is a form the user submits; its fields are escaped like any value.
  const form = errorPage({ title: 'T', text: 'x', returnTo: { action: 'https://app.example.com/cb', fields: { error: 'e', state: HOSTILE, iss: 'i', nonce: undefined }, host: 'app.example.com' } });
  assert.equal(form.headers.get('Location'), null);
  assert.match(form.headers.get('Content-Security-Policy'), /script-src 'none'/);
  const formBody = await form.text();
  assert.ok(formBody.includes('<form method="post" action="https://app.example.com/cb">'));
  assert.ok(formBody.includes('<input type="hidden" name="error" value="e">'));
  assert.ok(formBody.includes('<button type="submit">Return to app.example.com</button>'));
  assert.equal(formBody.includes('nonce'), false);
  assert.equal(formBody.includes('<img'), false);
});

test('domain, credentials, tile and home pages render and escape', async () => {
  const d = await domainPage({ provider, status: { configured: true, authenticator: 'auth.example.com', secure: true }, form: { redirectUri: HOSTILE, problem: HOSTILE } }).text();
  assert.equal(d.includes('class="badge'), false, 'a domain that is set up shows no badge, only problems do');
  assert.ok(d.includes('<body class="wide">'));
  assert.ok(d.includes('By connecting an app, you agree to our <a href="https://www.triauth.org/legal/terms"'), 'the notice links the Terms');
  assert.ok(d.includes('<button type="submit">Connect app</button>'), 'the button next to the notice');
  assert.ok(d.includes('href="https://www.triauth.org/legal/privacy"'));
  assert.ok(d.includes(provider.discovery));
  assert.ok(d.includes('copy its redirect URI. <span class="hint">Not sure where? <a href="https://www.triauth.org/everywhere/?q=OIDC" target="_blank" rel="noopener">Setup guides for popular apps <span aria-hidden="true">↗</span></a></span></li>'), 'step 1 links the showcase of guides');
  assert.equal((d.match(/<details class="more"/g) || []).length, 1, 'the provider settings are the only fold');
  assert.equal(d.includes('<img'), false);
  const c = await credentialsPage({ provider, credentials: { clientId: 'r_s', clientSecret: 'S', host: 'app.example.com', redirectUri: 'https://app.example.com/login/generic_oauth' } }).text();
  assert.ok(c.includes('<h2>Using Grafana?</h2>'));
  assert.ok(c.includes('client_secret = S'));
  assert.ok(c.includes('[auth.generic_oauth]'));
  const p = await credentialsPage({ provider, credentials: { clientId: 'r', clientSecret: null, host: 'app.example.com', redirectUri: 'https://app.example.com/cb' } }).text();
  assert.ok(p.includes('must use PKCE'));
  assert.equal(p.includes('<h2>Using '), false, 'an app not recognised gets no setup card');
  const tile = tilePage({ provider, host: 'app.example.com', url: 'https://app.example.com/' });
  assert.equal(tile.status, 200);
  assert.equal(tile.headers.get('Location'), null, 'the tile page never redirects by itself');
  const t = await tile.text();
  const links = [...t.matchAll(/<a\b[^>]*\bhref="([^"]*)"/g)].map((match) => match[1]);
  assert.ok(t.includes('<a class="button" href="https://app.example.com/" autofocus>Open app.example.com</a>'), 'the tile page offers the root of the app\'s host, with focus so that Enter continues');
  assert.ok(links.every((href) => href === '/' || href === 'https://app.example.com/' || href.startsWith('https://www.triauth.org/') || href === sourceUrl), 'and links nowhere else but the bridge home, triauth.org and its own source');
  assert.equal(t.includes('http-equiv'), false);
  assert.ok(t.includes('Sign in to <strong>app.example.com</strong> with your <strong>@example.com</strong> identifier'));
  assert.ok(t.includes(`<a href="${sourceUrl}">triauth-oidc v${version}</a>`), 'the footer names the version and links to the source of this build');
  const local = await tilePage({ provider, host: 'localhost:3000', url: 'http://localhost:3000/' }).text();
  assert.ok(local.includes('<a class="button" href="http://localhost:3000/" autofocus>Open localhost:3000</a>'));
  const h = await homePage({ problem: HOSTILE }).text();
  assert.equal(h.includes('<img'), false);
  assert.ok(h.includes('name="domain"'));
});
