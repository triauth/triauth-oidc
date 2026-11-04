/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// The apps the bridge knows by their redirect URI: the setup the credentials page shows for each,
// with a link to the app's own OpenID Connect guide.
//
// The redirect URI ends in a path that the app itself chose, such as Grafana's /login/generic_oauth,
// so the path tells which app asked, on any host and under any folder. The host says nothing: it is
// whatever name the app's owner gave the server. An app gets a setup card only when its setup is text
// to paste or run (a file, environment variables, a command). Apps set up in a web form, or with
// options that vary too much to fill in for them, get no card: the provider settings are what they
// need, and their guides live in the showcase on www.triauth.org, which the domain's page links.
//
// Each setup was checked against the app's documentation and source on 2026-10-20, and every guide
// link was opened on 2026-10-21 (each loads, and is about OpenID Connect). When an app changes its
// configuration or moves its docs, fix its entry here; nothing else knows about apps.
//
// The setup text holds the client secret, like the rest of the page, which shows it once. Values in
// Ruby are JSON-quoted, which Ruby reads the same way (a canonical redirect URI has no `#`, so no
// `#{`). The shell command holds only the domain, the client ID, the secret and the bridge's own URL,
// none of which can contain a quote.

import CONFIG from '../../config.js';
import { html } from './html.js';

const APPS = [
  {
    name: 'Grafana',
    path: '/login/generic_oauth',
    how: html`Paste this into <code>grafana.ini</code>, or enter the same values under Administration › Authentication › Generic OAuth.`,
    docs: 'https://grafana.com/docs/grafana/latest/setup-grafana/configure-access/configure-authentication/generic-oauth/',
    // With offline_access and use_refresh_token, Grafana renews its session through the bridge and
    // signs the person out when that fails (the device left DNS, or the session reached its limit),
    // instead of keeping a session of its own for 30 days. Without refresh tokens, Grafana would sign
    // people out when the access token expires, so both lines go only where the bridge issues them.
    setup: (provider, { clientId, clientSecret }) => [
      '[auth.generic_oauth]',
      'enabled = true',
      `name = ${provider.domain}`,
      `client_id = ${clientId}`,
      `client_secret = ${clientSecret ?? ''}`,
      `auth_url = ${provider.authorize}`,
      `token_url = ${provider.token}`,
      `api_url = ${provider.userinfo}`,
      `scopes = openid email profile groups${CONFIG.refreshTokens ? ' offline_access' : ''}`,
      'use_pkce = true',
      ...(CONFIG.refreshTokens ? ['use_refresh_token = true'] : []),
      'groups_attribute_path = groups',
    ],
  },
  {
    name: 'GitLab',
    path: '/users/auth/openid_connect/callback',
    how: html`Add this to <code>/etc/gitlab/gitlab.rb</code>, then run <code>sudo gitlab-ctl reconfigure</code>.`,
    docs: 'https://docs.gitlab.com/administration/auth/oidc/',
    setup: (provider, { clientId, clientSecret, redirectUri }) => [
      "gitlab_rails['omniauth_allow_single_sign_on'] = ['openid_connect']",
      '# To let new people in without an admin approving each account:',
      "# gitlab_rails['omniauth_block_auto_created_users'] = false",
      "gitlab_rails['omniauth_providers'] = [",
      '  {',
      '    name: "openid_connect",',
      `    label: ${ruby(provider.domain)},`,
      '    args: {',
      '      name: "openid_connect",',
      '      scope: ["openid", "profile", "email"],',
      '      response_type: "code",',
      `      issuer: ${ruby(provider.issuer)},`,
      '      discovery: true,',
      '      pkce: true,',
      '      client_options: {',
      `        identifier: ${ruby(clientId)},`,
      `        secret: ${ruby(clientSecret ?? '')},`,
      `        redirect_uri: ${ruby(redirectUri)}`,
      '      }',
      '    }',
      '  }',
      ']',
    ],
  },
  {
    name: 'Nextcloud',
    path: '/apps/user_oidc/code',
    how: html`Run this in your Nextcloud folder, with the <code>user_oidc</code> app installed. Each person's Nextcloud user ID is then their triauth address.`,
    docs: 'https://github.com/nextcloud/user_oidc',
    // PKCE is on by itself: user_oidc uses it when discovery lists S256, which the bridge's does.
    setup: (provider, { clientId, clientSecret }) => [
      `sudo -u www-data php occ user_oidc:provider ${shell(provider.domain)} \\`,
      `  --clientid=${shell(clientId)} \\`,
      `  --clientsecret=${shell(clientSecret ?? '')} \\`,
      `  --discoveryuri=${shell(provider.discovery)} \\`,
      '  --unique-uid=0',
    ],
  },
  {
    name: 'Outline',
    path: '/auth/oidc.callback',
    how: html`Add these to Outline's environment, then restart it. Outline reads the rest from discovery, and turns on PKCE.`,
    docs: 'https://docs.getoutline.com/s/hosting/doc/oidc-8CPBm6uC0I',
    setup: (provider, { clientId, clientSecret }) => [
      `OIDC_CLIENT_ID=${clientId}`,
      `OIDC_CLIENT_SECRET=${clientSecret ?? ''}`,
      `OIDC_ISSUER_URL=${provider.issuer}`,
      `OIDC_DISPLAY_NAME=${provider.domain}`,
    ],
  },
];

const ruby = (value) => JSON.stringify(value);
const shell = (value) => `'${value}'`;

/**
 * The app behind a redirect URI, with its setup filled in, or null for an app not listed.
 *
 * @param provider {object} - The domain's provider, with its URLs.
 * @param credentials {{clientId: string, clientSecret: (string|null), redirectUri: string}} - The
 *        credentials just created; the redirect URI was checked to be a canonical URL.
 * @returns {{name: string, how: Html, docs: string, setup: string}|null}
 */
export function appSetup(provider, credentials) {
  const path = new URL(credentials.redirectUri).pathname;
  const app = APPS.find((entry) => path.endsWith(entry.path));
  if (!app) {
    return null;
  }
  return { name: app.name, how: app.how, docs: app.docs, setup: app.setup(provider, credentials).join('\n') };
}
