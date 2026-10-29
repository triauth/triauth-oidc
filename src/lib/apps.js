/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// The apps the bridge knows by their redirect URI: the setup the credentials page shows for each, and
// the links to their own OpenID Connect guides that the domain's page lists.
//
// The redirect URI ends in a path that the app itself chose, such as Grafana's /login/generic_oauth,
// so the path tells which app asked, on any host and under any folder. The host says nothing: it is
// whatever name the app's owner gave the server. An app gets a setup card only when its setup is text
// to paste or run (a file, environment variables, a command). Many more apps are listed for their
// guide alone (MORE_GUIDES): they are set up in a web form, or with options that vary too much to
// fill in for them, and the provider settings are what they need.
//
// Each setup was checked against the app's documentation and source on 2026-10-20, and every guide
// link was opened on 2026-10-21 (each loads, and is about OpenID Connect). When an app changes its
// configuration or moves its docs, fix its entry here; nothing else knows about apps.
//
// The setup text holds the client secret, like the rest of the page, which shows it once. Values in
// Ruby are JSON-quoted, which Ruby reads the same way (a canonical redirect URI has no `#`, so no
// `#{`). The shell command holds only the domain, the client ID, the secret and the bridge's own URL,
// none of which can contain a quote.

import { html } from './html.js';

const APPS = [
  {
    name: 'Grafana',
    path: '/login/generic_oauth',
    how: html`Paste this into <code>grafana.ini</code>, or enter the same values under Administration › Authentication › Generic OAuth.`,
    docs: 'https://grafana.com/docs/grafana/latest/setup-grafana/configure-access/configure-authentication/generic-oauth/',
    // No refresh token: the bridge issues none, and Grafana would sign people out when the access
    // token expires. use_refresh_token stays at its default, false.
    setup: (provider, { clientId, clientSecret }) => [
      '[auth.generic_oauth]',
      'enabled = true',
      `name = ${provider.domain}`,
      `client_id = ${clientId}`,
      `client_secret = ${clientSecret ?? ''}`,
      `auth_url = ${provider.authorize}`,
      `token_url = ${provider.token}`,
      `api_url = ${provider.userinfo}`,
      'scopes = openid email profile groups',
      'use_pkce = true',
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

// Apps listed for their own OpenID Connect guide only, on the domain's page.
const MORE_GUIDES = [
  { name: 'Gitea', docs: 'https://docs.gitea.com/administration/authentication/' },
  { name: 'Argo CD', docs: 'https://argo-cd.readthedocs.io/en/stable/operator-manual/user-management/#existing-oidc-provider' },
  { name: 'Jenkins', docs: 'https://plugins.jenkins.io/oic-auth/' },
  { name: 'Portainer', docs: 'https://docs.portainer.io/admin/settings/authentication/oauth' },
  { name: 'Proxmox VE', docs: 'https://pve.proxmox.com/wiki/User_Management#pveum_openid' },
  { name: 'HashiCorp Vault', docs: 'https://developer.hashicorp.com/vault/docs/auth/jwt' },
  { name: 'kubectl (kubelogin)', docs: 'https://github.com/int128/kubelogin' },
  { name: 'BookStack', docs: 'https://www.bookstackapp.com/docs/admin/oidc-auth/' },
  { name: 'Mattermost', docs: 'https://docs.mattermost.com/administration-guide/onboard/sso-openidconnect' },
  { name: 'Matrix (Synapse)', docs: 'https://element-hq.github.io/synapse/latest/openid.html' },
  { name: 'Zammad', docs: 'https://admin-docs.zammad.org/en/latest/settings/security/third-party/openid-connect.html' },
  { name: 'Penpot', docs: 'https://help.penpot.app/technical-guide/configuration/#openid-connect' },
  { name: 'Vikunja', docs: 'https://vikunja.io/docs/openid/' },
  { name: 'Paperless-ngx', docs: 'https://docs.paperless-ngx.com/advanced_usage/#openid-connect-and-social-authentication' },
  { name: 'Immich', docs: 'https://docs.immich.app/administration/oauth/' },
  { name: 'Jellyfin (SSO plugin)', docs: 'https://github.com/9p4/jellyfin-plugin-sso' },
  { name: 'Audiobookshelf', docs: 'https://audiobookshelf.org/docs/documentation/server-management/oidc-authentication/' },
  { name: 'Mealie', docs: 'https://mealie.io/documentation/getting-started/authentication/oidc-v2/' },
  { name: 'Open WebUI', docs: 'https://docs.openwebui.com/features/authentication-access/auth/sso/' },
  { name: 'Cloudflare Access', docs: 'https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/generic-oidc/' },
  { name: 'Tailscale', docs: 'https://tailscale.com/docs/integrations/identity/custom-oidc' },
  { name: 'Headscale', docs: 'https://headscale.net/stable/ref/oidc/' },
  { name: 'Vaultwarden', docs: 'https://github.com/dani-garcia/vaultwarden/wiki/Enabling-SSO-support-using-OpenId-Connect' },
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

/**
 * Every app listed, with its own guide to setting up OpenID Connect, sorted by name, for the domain's
 * page.
 *
 * @returns {Array<{name: string, docs: string}>}
 */
export function appGuides() {
  return [...APPS, ...MORE_GUIDES]
    .map(({ name, docs }) => ({ name, docs }))
    .sort((a, b) => a.name.localeCompare(b.name, 'en', { sensitivity: 'base' }));
}
