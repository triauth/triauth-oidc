/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// A domain's provider.
//
// In OpenID Connect, the "issuer" is the identity provider's address. Every token names it in its
// `iss` claim, and apps find the provider's endpoints at `{issuer}/.well-known/openid-configuration`.
// This bridge is one provider per domain: the provider for identities at example.com is
// `https://oidc.triauth.org/example.com`, and it vouches for `…@example.com` only.
//
// This file turns a request URL into that provider. It reads the domain from the first path segment,
// requires it to be a domain name spelled the way identifiers spell it (lowercase), applies the
// optional DOMAINS allowlist, and builds the endpoint URLs that every other file uses.

import { Helpers } from 'triauth';

/**
 * Splits a request path into the domain and the rest of the path.
 *
 *   '/example.com'            -> {domain: 'example.com', rest: null}   (no trailing slash)
 *   '/example.com/'           -> {domain: 'example.com', rest: ''}
 *   '/example.com/authorize'  -> {domain: 'example.com', rest: 'authorize'}
 *
 * @param pathname {string} - The request path.
 * @returns {{domain: string, rest: (string|null)}|null} Null when the first segment is not a lowercase domain name.
 */
export function splitDomainPath(pathname) {
  const match = pathname.match(/^\/([^/]+)(?:\/(.*))?$/);
  if (!match || !isIdentifierDomain(match[1])) {
    return null;
  }
  return { domain: match[1], rest: match[2] ?? null };
}

/**
 * True for a domain name as it appears in identifiers: ASCII letters, digits and hyphens, at least
 * two labels, lowercase, no Punycode (`xn--`) labels, and no numeric final label.
 *
 * @param domain {*} - The candidate.
 * @returns {boolean}
 */
export function isIdentifierDomain(domain) {
  return typeof domain === 'string' && Helpers.isDomainName(domain) && domain === domain.toLowerCase();
}

/**
 * Applies the DOMAINS variable: a space-separated allowlist, or empty for any domain.
 *
 * @param env {object} - The Worker environment.
 * @param domain {string} - A domain that passed isIdentifierDomain.
 * @returns {boolean}
 */
export function domainAllowed(env, domain) {
  const allowed = String(env.DOMAINS || '').trim().split(/\s+/).filter(Boolean);
  return allowed.length === 0 || allowed.includes(domain);
}

/**
 * The provider for a domain: its issuer and every URL under it.
 *
 * @param origin {string} - The bridge's origin, e.g. 'https://oidc.triauth.org'.
 * @param domain {string} - The domain, e.g. 'example.com'.
 * @returns {Readonly<object>}
 */
export function providerFor(origin, domain) {
  const issuer = `${origin}/${domain}`;

  return Object.freeze({
    domain,
    origin,
    host: new URL(origin).host,
    issuer,
    page: `${issuer}/`,
    credentials: `${issuer}/credentials`,
    discovery: `${issuer}/.well-known/openid-configuration`,
    jwks: `${issuer}/jwks`,
    authorize: `${issuer}/authorize`,
    login: `${issuer}/login`,
    token: `${issuer}/token`,
    userinfo: `${issuer}/userinfo`,

    // Every app has its own address on the bridge, named after its host. The authenticator shows
    // and remembers this base URL as "the website" that asks for the sign-in (see callback.js).
    appBase: (appHost) => `${issuer}/apps/${appHost}/`,
    callback: (appHost, flowId) => `${issuer}/apps/${appHost}/callback?f=${flowId}`,
  });
}
