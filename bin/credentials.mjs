#!/usr/bin/env node
/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */
// Creates app credentials from the command line, with the same recipe as the domain page:
//
//   node bin/credentials.mjs example.com https://grafana.example.com/login/generic_oauth
//   node bin/credentials.mjs example.com https://photos.example.com/auth/login https://photos.example.com/user-settings
//   node bin/credentials.mjs example.com https://cli.example.com/callback --public
//   node bin/credentials.mjs example.com https://grafana.example.com/login/generic_oauth --group admins
//   node bin/credentials.mjs example.com https://app.example.com/cb --origin https://oidc.example.net
//
// Nothing is stored anywhere; keep the secret in the app's settings only.

import { createCredentials, redirectUriProblem, publicClientProblem, isGroupName, MAX_REDIRECT_URIS } from '../src/lib/credentials.js';
import { isIdentifierDomain, providerFor } from '../src/lib/provider.js';

const args = process.argv.slice(2);
const flags = { public: false, group: null, origin: 'https://oidc.triauth.org' };
const positional = [];

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--public') {
    flags.public = true;
  } else if (args[i] === '--group') {
    flags.group = args[++i];
  } else if (args[i] === '--origin') {
    flags.origin = args[++i];
  } else {
    positional.push(args[i]);
  }
}

const [domain, ...redirectUris] = positional;

if (!isIdentifierDomain(domain) || redirectUris.length === 0 || redirectUris.length > MAX_REDIRECT_URIS) {
  console.error(`Usage: node bin/credentials.mjs <domain> <redirect-uri> [<redirect-uri> ...] [--public] [--group <name>] [--origin https://oidc.triauth.org]\n` +
    `An app has one redirect URI, or up to ${MAX_REDIRECT_URIS} when its settings list several.`);
  process.exit(1);
}

const provider = providerFor(flags.origin, domain);
for (const redirectUri of redirectUris) {
  const problem = redirectUriProblem(redirectUri, provider.host) ?? (flags.public ? publicClientProblem(redirectUri) : null);
  if (problem) {
    console.error(`${redirectUri}: ${problem}`);
    process.exit(1);
  }
}
if (flags.group !== null && !isGroupName(flags.group)) {
  console.error(`A group name has lowercase letters, digits, and single hyphens, at most 20 characters, for example admins or project-x. Give the part before @${domain}.`);
  process.exit(1);
}

const credentials = await createCredentials(domain, redirectUris, { secret: !flags.public, group: flags.group });

console.log(`Issuer:          ${provider.issuer}`);
console.log(`Client ID:       ${credentials.clientId}`);
console.log(`Client secret:   ${credentials.clientSecret ?? '(none: this app must use PKCE)'}`);
credentials.redirectUris.forEach((uri, i) => console.log(`${(i === 0 ? 'Redirect URI:' : '').padEnd(17)}${uri}`));
console.log(`Who signs in:    ${credentials.group ? `members of ${credentials.group}@${domain} only` : `everyone at ${domain}`}`);
console.log('');
console.log(`Discovery:       ${provider.discovery}`);
console.log(`Auth URL:        ${provider.authorize}`);
console.log(`Token URL:       ${provider.token}`);
console.log(`Userinfo URL:    ${provider.userinfo}`);
console.log(`JWKS URL:        ${provider.jwks}`);
