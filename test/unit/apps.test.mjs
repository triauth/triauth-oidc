// App setups (src/lib/apps.js): the redirect URI's path names the app, and its setup carries the
// credentials and the provider.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import config from '../../config.js';
import { appSetup } from '../../src/lib/apps.js';
import { providerFor } from '../../src/lib/provider.js';

const provider = providerFor('https://oidc.test', 'example.com');
const credentials = (redirectUri, clientSecret = 'S3cr3t') => ({ clientId: 'app.example.com~a~b', clientSecret, host: new URL(redirectUri).host, redirectUri });
const setupFor = (redirectUri, clientSecret) => appSetup(provider, credentials(redirectUri, clientSecret)).setup;

test('the path names the app, on any host and under any folder; the host name does not', () => {
  const named = {
    'https://dash.example.com/login/generic_oauth': 'Grafana',
    'https://example.com/grafana/login/generic_oauth': 'Grafana',
    'https://code.example.com/users/auth/openid_connect/callback': 'GitLab',
    'https://cloud.example.com/apps/user_oidc/code': 'Nextcloud',
    'https://cloud.example.com/index.php/apps/user_oidc/code': 'Nextcloud',
    'https://wiki.example.com/auth/oidc.callback': 'Outline',
  };
  for (const [uri, name] of Object.entries(named)) {
    assert.equal(appSetup(provider, credentials(uri))?.name, name, uri);
  }
  for (const uri of ['https://grafana.example.com/callback', 'https://gitlab.example.com/', 'https://dash.example.com/login/generic_oauth/x', 'https://team.cloudflareaccess.com/cdn-cgi/access/callback']) {
    assert.equal(appSetup(provider, credentials(uri)), null, uri);
  }
});

test('each setup carries the credentials and the provider', () => {
  const grafana = setupFor('https://dash.example.com/login/generic_oauth');
  assert.match(grafana, /^\[auth\.generic_oauth\]$/m);
  assert.match(grafana, /^client_id = app\.example\.com~a~b$/m);
  assert.match(grafana, /^client_secret = S3cr3t$/m);
  assert.match(grafana, /^auth_url = https:\/\/oidc\.test\/example\.com\/authorize$/m);
  assert.match(grafana, /^use_pkce = true$/m);
  // The refresh lines go only where the bridge issues refresh tokens, which it does unless told otherwise.
  assert.match(grafana, /^scopes = openid email profile groups offline_access$/m);
  assert.match(grafana, /^use_refresh_token = true$/m);
  config.refreshTokens = false;
  try {
    const without = setupFor('https://dash.example.com/login/generic_oauth');
    assert.match(without, /^scopes = openid email profile groups$/m);
    assert.doesNotMatch(without, /refresh/);
  } finally {
    config.refreshTokens = true;
  }

  const gitlab = setupFor('https://code.example.com/users/auth/openid_connect/callback');
  assert.ok(gitlab.includes('issuer: "https://oidc.test/example.com",'));
  assert.ok(gitlab.includes('identifier: "app.example.com~a~b",'));
  assert.ok(gitlab.includes('secret: "S3cr3t",'));
  assert.ok(gitlab.includes('redirect_uri: "https://code.example.com/users/auth/openid_connect/callback"'));
  assert.ok(gitlab.includes('discovery: true,') && gitlab.includes('pkce: true,'));

  const nextcloud = setupFor('https://cloud.example.com/index.php/apps/user_oidc/code');
  assert.ok(nextcloud.startsWith("sudo -u www-data php occ user_oidc:provider 'example.com' \\\n"));
  assert.ok(nextcloud.includes("--clientid='app.example.com~a~b'"));
  assert.ok(nextcloud.includes("--clientsecret='S3cr3t'"));
  assert.ok(nextcloud.includes("--discoveryuri='https://oidc.test/example.com/.well-known/openid-configuration'"));

  const outline = setupFor('https://wiki.example.com/auth/oidc.callback');
  assert.equal(outline, 'OIDC_CLIENT_ID=app.example.com~a~b\nOIDC_CLIENT_SECRET=S3cr3t\nOIDC_ISSUER_URL=https://oidc.test/example.com\nOIDC_DISPLAY_NAME=example.com');
});

test('an app without a secret gets an empty one, and Ruby strings are quoted', () => {
  assert.match(setupFor('https://dash.example.com/login/generic_oauth', null), /^client_secret = $/m);
  const uri = 'https://code.example.com/a"b\\c/users/auth/openid_connect/callback';
  const line = setupFor(uri).split('\n').find((text) => text.includes('redirect_uri:'));
  assert.equal(JSON.parse(line.replace(/^\s*redirect_uri: /, '')), uri);
});
