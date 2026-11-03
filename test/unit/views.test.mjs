// Views (src/views/): pure functions of plain values. The two rules that keep the split safe are
// checked by reading the files: a view imports only the HTML tag, the partials and the stylesheet, and
// `raw` is used in exactly two places.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Html } from '../../src/lib/html.js';
import layout from '../../src/views/layout.js';
import home from '../../src/views/home.js';
import domain from '../../src/views/domain.js';
import credentials from '../../src/views/credentials.js';
import signIn from '../../src/views/sign-in.js';
import error from '../../src/views/error.js';
import tile from '../../src/views/tile.js';
import formPost from '../../src/views/form-post.js';
import { providerFor } from '../../src/lib/provider.js';

const dir = fileURLToPath(new URL('../../src/views/', import.meta.url));
const files = readdirSync(dir).filter((name) => name.endsWith('.js')).sort();
const HOSTILE = `"><img src=x onerror=alert(1)><script>alert('x')</script>&`;
const provider = providerFor('https://oidc.test', 'example.com');

test('a view imports only html.js, the partials and the stylesheet, and uses no platform API', () => {
  assert.deepEqual(files, ['credentials.js', 'domain.js', 'error.js', 'form-post.js', 'home.js', 'layout.js', 'partials.js', 'sign-in.js', 'style.js', 'tile.js']);
  for (const file of files) {
    const text = readFileSync(dir + file, 'utf8');
    for (const [, specifier] of text.matchAll(/from '([^']+)'/g)) {
      assert.ok(['../lib/html.js', './partials.js', './style.js'].includes(specifier), `${file} imports ${specifier}`);
    }
    assert.doesNotMatch(text, /\b(Response|Request|Headers|fetch|crypto|env|process)\b/, `${file} touches a platform API`);
  }
});

test('raw is used only by the layout (the stylesheet) and the form_post view (the hashed script)', () => {
  for (const file of files) {
    const uses = (readFileSync(dir + file, 'utf8').match(/\braw\(/g) || []).length;
    assert.equal(uses, file === 'layout.js' || file === 'form-post.js' ? 1 : 0, `${file} uses raw ${uses} time(s)`);
  }
});

test('every view renders hostile values harmlessly and returns an Html fragment', () => {
  const rendered = [
    home({ problem: HOSTILE }),
    domain({ provider, status: { configured: true, authenticator: HOSTILE, secure: true }, form: { redirectUri: HOSTILE, publicClient: true, limitGroup: true, group: HOSTILE, problem: HOSTILE } }),
    credentials({ provider, credentials: { clientId: HOSTILE, clientSecret: HOSTILE, host: HOSTILE, redirectUri: HOSTILE }, app: { name: HOSTILE, how: HOSTILE, docs: 'https://docs.example.com/', setup: HOSTILE } }),
    credentials({ provider, credentials: { clientId: 'c', clientSecret: 'S', host: 'h', redirectUri: 'https://h/cb', group: HOSTILE }, app: null }),
    credentials({ provider, credentials: { clientId: 'c', clientSecret: null, host: HOSTILE, redirectUri: HOSTILE }, app: null }),
    signIn({ domain: 'example.com', host: HOSTILE, redirectUri: HOSTILE, loginUrl: provider.login, appAddress: HOSTILE, username: HOSTILE, error: HOSTILE, fields: { state: HOSTILE, nonce: undefined } }),
    error({ title: HOSTILE, text: HOSTILE, returnTo: { url: 'https://app.example.com/cb', host: HOSTILE } }),
    error({ title: 'T', text: 'x', returnTo: { action: 'https://app.example.com/cb', fields: { error: HOSTILE }, host: 'app.example.com' } }),
    tile({ domain: 'example.com', host: HOSTILE, url: 'https://app.example.com/' }),
    formPost({ action: 'https://app.example.com/cb', fields: { code: HOSTILE, state: HOSTILE }, host: HOSTILE }),
  ];
  for (const fragment of rendered) {
    assert.ok(fragment instanceof Html);
    const text = fragment.toString();
    assert.equal(text.includes('<img'), false);
    assert.equal(text.includes("<script>alert"), false);
    assert.ok(text.includes('&lt;script&gt;'));
  }
  // Step 1 links the showcase of guides on www.triauth.org, in a new tab so the form keeps what was typed.
  const steps = domain({ provider, status: null, form: {} }).toString();
  assert.ok(steps.includes('copy its redirect URI. <span class="hint">Not sure where? <a href="https://www.triauth.org/everywhere/?q=OIDC" target="_blank" rel="noopener">Setup guides for popular apps <span aria-hidden="true">↗</span></a></span></li>'));
  assert.equal((steps.match(/<details class="more"/g) || []).length, 1, 'no fold of guides below the settings');

  // The provider settings fold on the domain's page and stay open on the credentials page.
  assert.ok(domain({ provider, status: null, form: {} }).toString().includes('<details class="more">\n<summary>View provider settings</summary>'));
  assert.equal(domain({ provider, status: null, form: {} }).toString().includes('<details class="more" open'), false);
  assert.equal(credentials({ provider, credentials: { clientId: 'c', clientSecret: 'S', host: 'h', redirectUri: 'https://h/cb' }, app: null }).toString().includes('<details'), false);

  // The domain page's other two states, which show no value from outside.
  assert.ok(domain({ provider, status: { configured: false }, form: {} }).toString().includes("example.com isn't set up for triauth yet"));
  assert.ok(domain({ provider, status: { configured: null }, form: {} }).toString().includes("DNS couldn't be read just now"));
  assert.equal(domain({ provider, status: null, form: {} }).toString().includes('class="badge'), false, 'no status, no badge');
  assert.ok(domain({ provider, status: { configured: true, authenticator: 'auth.example.com', secure: false }, form: {} }).toString().includes('checkbox" name="public" value="1" >'));

  // The group limit: a box, a hint that links to triauth's page on groups, and in the column of its
  // label the field that the stylesheet shows while the box is checked.
  const fresh = domain({ provider, status: null, form: {} }).toString();
  assert.ok(fresh.includes('name="limit_group" value="1" aria-describedby="limit_group_hint" > <div>\n<label for="limit_group">Limit sign-ins to a specific group</label>'));
  assert.ok(fresh.includes('<p id="limit_group_hint" class="hint">Only the group\'s members can sign in to the app. <a href="https://www.triauth.org/identity/groups" target="_blank" rel="noopener">How groups work <span aria-hidden="true">↗</span></a></p>\n<div class="reveal">\n<label for="group">Group name</label>'));
  assert.ok(fresh.includes('name="group" value=""'));
  assert.ok(fresh.includes('<span class="suffix">@example.com</span>'));
  const sentBack = domain({ provider, status: null, form: { redirectUri: 'https://h/cb', limitGroup: true, group: 'admins', problem: 'x' } }).toString();
  assert.ok(sentBack.includes('name="limit_group" value="1" aria-describedby="limit_group_hint" checked>'));
  assert.ok(sentBack.includes('name="group" value="admins"'));

  // The credentials page says who will be able to sign in.
  const forGroup = credentials({ provider, credentials: { clientId: 'c', clientSecret: 'S', host: 'h', redirectUri: 'https://h/cb', group: 'admins' }, app: null }).toString();
  assert.ok(forGroup.includes('Once you copy these settings to h members of the <strong>admins@example.com</strong> group will be able to sign in there with triauth.'));
  const forEveryone = credentials({ provider, credentials: { clientId: 'c', clientSecret: 'S', host: 'h', redirectUri: 'https://h/cb', group: null }, app: null }).toString();
  assert.ok(forEveryone.includes('Once you copy these settings to h everyone with an identifier under the <strong>@example.com</strong> domain will be able to sign in there with triauth.'));

  assert.ok(layout({ title: 'T', body: home({ problem: null }), wide: true }).toString().includes('<body class="wide">'));
  const doc = layout({ title: HOSTILE, body: home({ problem: null }) }).toString();
  assert.ok(doc.startsWith('<!doctype html>'));
  assert.ok(doc.includes('<body>\n<header><a href="/">') && doc.includes('<main>') && doc.includes('<footer>'));
  assert.equal(doc.includes('<img'), false);
  assert.ok(doc.includes('<style>'), 'the stylesheet is inlined');
});

test('the sign-in page focuses the empty field, or the Continue button when the username is prefilled', () => {
  const render = (username, error = null) => signIn({ domain: 'example.com', host: 'app.example.com', redirectUri: 'https://app.example.com/cb', loginUrl: provider.login, appAddress: 'a', username, error, fields: {} }).toString();
  const field = (text) => text.match(/<input id="username"[^>]*>/)[0];
  const button = (text) => text.match(/<button type="submit"[^>]*>/)[0];

  const empty = render('');
  assert.ok(field(empty).endsWith(' required autofocus>'));
  assert.equal(button(empty), '<button type="submit" >');

  // A remembered username or a login_hint: Enter continues; Shift+Tab selects the whole value to retype it.
  const prefilled = render('john');
  assert.ok(field(prefilled).endsWith(' required >'));
  assert.equal(button(prefilled), '<button type="submit" autofocus>');

  // After an error the value needs fixing, so the field takes focus again.
  const failed = render('john', 'Type only the part before @example.com.');
  assert.ok(field(failed).endsWith(' required autofocus>'));
  assert.equal(button(failed), '<button type="submit" >');
});
