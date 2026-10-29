/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// App credentials: the client ID and the client secret.
//
// An OpenID Connect app is set up with a client ID (its name at the provider), a client secret (its
// password for the provider's /token endpoint), and a redirect URI (where the provider sends the
// browser back). Providers usually keep a registry of these. This bridge keeps none: the client ID is
// computed from the redirect URI, a fingerprint of the secret, and the app's options, so the bridge
// checks an app by recomputing its ID, and nothing about apps is stored anywhere.
//
//   secret     base64url of 32 random bytes, 43 characters                  (apps that keep a secret)
//   s          the first 26 characters of base32(SHA-256("triauth-oidc/v1/secret" 0 secret))
//   options    the app's settings, each "key-value", sorted, joined by "_"   g-admins
//   rest       s and the options, joined by "_"                              (no s without a secret)
//   r          the first 26 characters of base32(SHA-256("triauth-oidc/v1/client" 0 domain 0 redirect URI 0 rest))
//   client ID  r, then "_" and rest when rest is not empty
//
// base32 is RFC 4648, lowercase, unpadded: 26 characters carry 130 bits. The zeros are zero bytes
// between the fields. Client IDs are case-sensitive, and use only lowercase letters, digits, "_", "-"
// and ".", which pass unchanged through URLs, Basic auth, config files, and shells.
//
// The redirect URI goes into r with "/" for an empty path, so https://pve.example.com:8006 and
// https://pve.example.com:8006/, one URL in two spellings, have one client ID.
//
// The options are the bridge's only per-app settings (OPTIONS below). An option is a key, one letter,
// then "-" and a value; the value starts after the first "-", so it may contain more hyphens, and never
// contains "_". Options only narrow what an app may do, because anyone can make a client ID with any
// options. Each set of options has one spelling (sorted, each key once, canonical values), and a client
// ID with a key the bridge does not know is refused, so no rule is ever skipped.
//
// What follows: anyone can compute an ID, so nothing needs a key or a registry; pointing an existing
// ID at another redirect URI, or changing its options, needs a 130-bit second preimage; a secret that
// fits an existing `s` needs a 130-bit preimage; each client ID has exactly one redirect URI; a new
// secret, a new redirect URI, or new options mean a new client ID.

import { Helpers, LIMITS, validate } from 'triauth';

export const SECRET_LENGTH = 43;          // base64url of 32 bytes
const FINGERPRINT_LENGTH = 26;            // base32 characters, 130 bits
const MAX_CLIENT_ID_LENGTH = 191;         // what some apps store at most (django-allauth); PLAN.md, section 5
const SECRET_LABEL = 'triauth-oidc/v1/secret';
const CLIENT_LABEL = 'triauth-oidc/v1/client';

// r, then s when the app has a secret, then the options. The part after r is s when it has no "-";
// every option has one.
const CLIENT_ID_REGEXP = /^([a-z2-7]{26})(?:_([a-z2-7]{26}))?((?:_[a-z]-[a-z0-9.-]+)*)$/;

// The options the bridge knows, by key: the property of a parsed client that holds the value, and the
// check of the value. The longest client ID they allow has 76 characters.
const OPTIONS = {
  g: { name: 'group', valid: isGroupName },   // only the members of this group at the domain may sign in
};

/**
 * Checks a redirect URI. Canonical https URLs only, by triauth's own URL rules (a lowercase host name
 * or an IPv4 address, no Punycode), or http://localhost for development, without a fragment, and
 * never on the bridge's own host (its sign-in page would then read "sign in to oidc.triauth.org"). A
 * URI without a path, such as https://pve.example.com:8006, is checked with the path "/".
 *
 * @param redirectUri {*} - The candidate.
 * @param bridgeHost {string} - The bridge's own host, e.g. 'oidc.triauth.org'.
 * @returns {string|null} A reason when the URI is refused, null when it is fine.
 */
export function redirectUriProblem(redirectUri, bridgeHost) {
  if (typeof redirectUri !== 'string' || redirectUri === '') {
    return 'The redirect URI is missing.';
  }

  const uri = withRootPath(redirectUri);
  if (!Helpers.isCanonicalUrl(uri) || (!uri.startsWith('https://') && new URL(uri).hostname !== 'localhost')) {
    return 'The redirect URI must be a canonical https:// URL (or http://localhost for development): lowercase host name or IPv4 address, no user info, no "." or ".." segments.';
  }
  if (redirectUri.includes('#')) {
    return 'The redirect URI must not have a fragment (#).';
  }
  const hostname = new URL(redirectUri).hostname;
  const bridgeHostname = bridgeHost.split(':')[0];
  if (hostname === bridgeHostname || hostname.endsWith('.' + bridgeHostname)) {
    return 'The redirect URI must not be on this bridge\'s own host, on any port, or under it.';
  }
  return null;
}

/**
 * Checks that an app without a secret has a domain name or localhost in its redirect URI. Anyone can
 * start a sign-in with such an app's client ID and a PKCE verifier of their own, so only the redirect
 * URI keeps its codes from others, and an IP address or a name without a dot can be someone else's
 * machine on another network.
 *
 * @param redirectUri {string} - A redirect URI, already checked with redirectUriProblem.
 * @returns {string|null} A reason when such an app must keep a secret, null when it may go without.
 */
export function publicClientProblem(redirectUri) {
  const hostname = new URL(redirectUri).hostname;
  if (hostname === 'localhost' || Helpers.isDomainName(hostname)) {
    return null;
  }
  return 'An app that can\'t keep a secret needs a domain name in its redirect URI. On another network, the same address can be someone else\'s machine.';
}

/**
 * True when two redirect URIs are one URL: equal once an empty path is written "/".
 *
 * @param a {string} - A redirect URI, already checked with redirectUriProblem.
 * @param b {string} - Another, checked the same way.
 * @returns {boolean}
 */
export function sameRedirectUri(a, b) {
  return withRootPath(a) === withRootPath(b);
}

/**
 * The host an app is known by: the redirect URI's host, with ':port' when it has one.
 *
 * @param redirectUri {*} - A redirect URI.
 * @returns {string|null} Null when it is not a URL at all.
 */
export function appHost(redirectUri) {
  try {
    return new URL(redirectUri).host;
  } catch {
    return null;
  }
}

/**
 * The root URL of an app's host, for the page behind the app's address on the bridge: https, or http
 * for localhost, as a redirect URI would have it. Null when no redirect URI could have this host
 * (redirectUriProblem's rules, which keep out the bridge's own host), so the page links only where an
 * app could have sent a sign-in from. The scheme is a guess for localhost, where https is rare.
 *
 * @param host {string} - The app's host, as in the address's path: a host name or IPv4 address, with an optional port.
 * @param bridgeHost {string} - The bridge's own host, e.g. 'oidc.triauth.org'.
 * @returns {string|null}
 */
export function appRootUrl(host, bridgeHost) {
  const url = `${host.split(':')[0] === 'localhost' ? 'http' : 'https'}://${host}/`;
  return redirectUriProblem(url, bridgeHost) === null ? url : null;
}

// The longest group name triauth accepts: one name grammar for device and group names, ASCII-only, so
// bytes are characters.
const GROUP_NAME_MAX_LENGTH = LIMITS.deviceNameBytesize;

/**
 * True for a group name as triauth spells it in `groups` records (Triauth.validate's `groupName` rule):
 * lowercase letters and digits joined by single hyphens, at most 20 characters. The domain is not part
 * of it: 'admins' is admins@example.com.
 *
 * @param name {*} - The candidate.
 * @returns {boolean}
 */
export function isGroupName(name) {
  return validate({ groupName: name }).valid;
}

/**
 * Checks a group name for the credentials form, as redirectUriProblem checks the redirect URI: the
 * message to show when triauth refuses the name, worded by triauth's reason, or null when it is fine.
 *
 * @param name {string} - The name as typed, lowercased and without '@domain' (the endpoint does that).
 * @param domain {string} - The domain, for the wording.
 * @returns {string|null}
 */
export function groupNameProblem(name, domain) {
  const { valid, errors } = validate({ groupName: name });
  if (valid) {
    return null;
  }
  switch (errors[0].reason) {
    case 'empty':
      return 'Type the name of the group whose members may sign in.';
    case 'too_long':
      return `A group name has at most ${GROUP_NAME_MAX_LENGTH} characters.`;
    default:
      return `A group name has lowercase letters and digits, joined by single hyphens, for example admins or project-x. Type the part before @${domain}.`;
  }
}

/**
 * A fresh client secret: base64url of 32 random bytes.
 *
 * @returns {string} 43 characters.
 */
export function newSecret() {
  return Helpers.arrayBufferToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

/**
 * Creates credentials for an app. Nothing is stored.
 *
 * @param domain {string} - The provider's domain, e.g. 'example.com'.
 * @param redirectUri {string} - The app's redirect URI, already checked with redirectUriProblem.
 * @param [options] {{secret?: boolean, group?: (string|null)}} - `secret: false` for an app that cannot
 *        keep a secret; `group` to let only that group's members sign in, already checked with isGroupName.
 * @returns {Promise<{clientId: string, clientSecret: (string|null), host: string, redirectUri: string, domain: string, group: (string|null)}>}
 */
export async function createCredentials(domain, redirectUri, { secret = true, group = null } = {}) {
  return credentialsFor(domain, redirectUri, secret ? newSecret() : null, { group });
}

/**
 * The recipe itself: the credentials for a given secret (or none) and options.
 *
 * @param domain {string} - The provider's domain.
 * @param redirectUri {string} - The app's redirect URI, already checked with redirectUriProblem.
 * @param clientSecret {string|null} - The 43-character secret, or null for an app without one.
 * @param [options] {{group?: (string|null)}} - The app's options; a value that is not valid throws.
 * @returns {Promise<{clientId: string, clientSecret: (string|null), host: string, redirectUri: string, domain: string, group: (string|null)}>}
 */
export async function credentialsFor(domain, redirectUri, clientSecret, options = {}) {
  const items = Object.entries(OPTIONS)
    .filter(([, option]) => options[option.name] !== undefined && options[option.name] !== null)
    .map(([key, option]) => {
      if (!option.valid(options[option.name])) {
        throw new TypeError(`Not a valid ${option.name}: ${options[option.name]}`);
      }
      return `${key}-${options[option.name]}`;
    })
    .sort();
  const s = clientSecret === null ? '' : await secretFingerprint(clientSecret);
  const rest = [s, ...items].filter(Boolean).join('_');
  const r = await clientFingerprint(domain, redirectUri, rest);

  return {
    clientId: rest === '' ? r : `${r}_${rest}`,
    clientSecret,
    host: appHost(redirectUri),
    redirectUri,
    domain,
    group: options.group ?? null,
  };
}

/**
 * Takes a client ID apart. It does not check the fingerprints; checkClient does.
 *
 * @param clientId {*} - The client ID as an app sent it.
 * @returns {{r: string, s: string, rest: string, confidential: boolean, group: (string|null)}|null} Null
 *          when it is not a client ID of this bridge. `s` is '' for an app without a secret; `rest` is
 *          everything after r, which r covers.
 */
export function parseClientId(clientId) {
  if (typeof clientId !== 'string' || clientId.length > MAX_CLIENT_ID_LENGTH) {
    return null;
  }
  const match = clientId.match(CLIENT_ID_REGEXP);
  if (!match) {
    return null;
  }
  const [, r, s = '', items] = match;
  const options = optionsOf(items === '' ? [] : items.slice(1).split('_'));
  if (!options) {
    return null;
  }
  return { r, s, rest: clientId.slice(r.length + 1), confidential: s !== '', ...options };
}

/**
 * Checks that a client ID was made for this domain and this redirect URI, by recomputing it.
 *
 * @param domain {string} - The provider's domain.
 * @param clientId {*} - The client ID from the request.
 * @param redirectUri {*} - The redirect URI from the request, already checked with redirectUriProblem.
 * @returns {Promise<{host: string, s: string, confidential: boolean, group: (string|null)}|null>} The
 *          parsed client with the host it is known by, or null when the checks fail.
 */
export async function checkClient(domain, clientId, redirectUri) {
  const client = parseClientId(clientId);
  const host = appHost(redirectUri);
  if (!client || typeof redirectUri !== 'string' || host === null) {
    return null;
  }
  const r = await clientFingerprint(domain, redirectUri, client.rest);
  return equalStrings(r, client.r) ? { ...client, host } : null;
}

/**
 * Checks an app's secret against the fingerprint in its client ID.
 *
 * @param client {{s: string, confidential: boolean}} - A parsed client, from checkClient.
 * @param secret {*} - The secret the app sent.
 * @returns {Promise<boolean>}
 */
export async function checkSecret(client, secret) {
  if (!client.confidential || typeof secret !== 'string' || secret.length !== SECRET_LENGTH || !Helpers.isBase64UrlString(secret)) {
    return false;
  }
  return equalStrings(await secretFingerprint(secret), client.s);
}

/**
 * Applies the app's options to an identity that has just signed in.
 *
 * @param client {{group: (string|null)}} - A parsed client.
 * @param claims {{groups: Array<string>}} - The identity's claims, from a verified sign-in (triauth.js).
 * @param domain {string} - The provider's domain.
 * @returns {string|null} The reason, for the sign-in page, when the options keep the identity out; null when they let it in.
 */
export function refusalFor(client, claims, domain) {
  if (client.group !== null && !claims.groups.includes(`${client.group}@${domain}`)) {
    return `Only members of ${client.group}@${domain} can sign in to this app.`;
  }
  return null;
}

/**
 * Reads the options of a client ID: sorted by key, each key once, every key known, every value valid.
 *
 * @param items {Array<string>} - The options, each "key-value".
 * @returns {{group: (string|null)}|null} Null when the options are not in their one spelling.
 */
function optionsOf(items) {
  const options = Object.fromEntries(Object.values(OPTIONS).map(({ name }) => [name, null]));
  for (const [i, item] of items.entries()) {
    const [key, value] = [item[0], item.slice(2)];
    const option = OPTIONS[key];
    if (!option || !option.valid(value) || (i > 0 && items[i - 1][0] >= key)) {
      return null;
    }
    options[option.name] = value;
  }
  return options;
}

async function secretFingerprint(secret) {
  return fingerprint(SECRET_LABEL, [secret]);
}

async function clientFingerprint(domain, redirectUri, rest) {
  return fingerprint(CLIENT_LABEL, [domain, withRootPath(redirectUri), rest]);
}

/**
 * The URI with "/" for an empty path, as browsers request it: https://pve.example.com:8006 becomes
 * https://pve.example.com:8006/, the same URL (RFC 3986 §6.2.3). Any other path is left alone. The
 * result is used only once redirectUriProblem has checked it against triauth's grammar.
 */
function withRootPath(uri) {
  return uri.replace(/^(https?:\/\/[^/?#]*)(?=[?#]|$)/, '$1/');
}

/**
 * base32(SHA-256(label 0 part 0 part ...)), lowercase, cut to FINGERPRINT_LENGTH.
 */
async function fingerprint(label, parts) {
  const encoder = new TextEncoder();
  const pieces = [encoder.encode(label)];
  for (const part of parts) {
    pieces.push(Uint8Array.of(0), encoder.encode(part));
  }
  const input = new Uint8Array(pieces.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const piece of pieces) {
    input.set(piece, offset);
    offset += piece.length;
  }
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
  return Helpers.uInt8ArrayToBase32(digest).toLowerCase().slice(0, FINGERPRINT_LENGTH);
}

/**
 * Compares two strings in time that does not depend on where they differ.
 */
function equalStrings(a, b) {
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  if (x.length !== y.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < x.length; i++) {
    diff |= x[i] ^ y[i];
  }
  return diff === 0;
}
