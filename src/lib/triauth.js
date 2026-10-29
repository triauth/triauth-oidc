/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// The triauth side of a sign-in.
//
// triauth-js does the protocol work. This file is the glue around it: the DNS-over-HTTPS resolver
// stack, the two calls that make a sign-in (stage 1 issues a challenge and finds the user's
// authenticator in DNS; stage 3 verifies the signed response against the keys in the user's DNS
// records), the claims the bridge derives from a verified sign-in, and the texts shown for triauth's
// error codes. Nothing else in the bridge imports triauth-js for protocol work.

import * as Triauth from 'triauth';
import CONFIG from '../../config.js';

// The library's DoH JSON resolvers over the Worker's fetch. The TXT options serve presentation-form
// providers (Cloudflare) and are harmless on logical-form ones (Google). With two or more endpoints, a
// MultiResolver keeps only the records that every endpoint returned.
const DNS_JSON_OPTIONS = { retries: 1, timeout: 5000, normalizeTxtRecords: true, decodeTxtRecords: true };

let resolver = null;   // built on first use, so tests may adjust CONFIG.doh after this module loads

/**
 * Whether a domain is set up for triauth: its `triauth` DNS record, which names the authenticator.
 *
 * @param env {object} - The Worker environment.
 * @param domain {string} - The domain.
 * @returns {Promise<{configured: true, authenticator: string, secure: boolean}|{configured: false}|{configured: null}>}
 *          `configured: null` when DNS could not be read right now.
 */
export async function domainStatus(env, domain) {
  try {
    const endpoint = new Triauth.AuthenticationEndpoint(domain, cfg(env));
    if (!(await endpoint.resolve())) {
      return { configured: false };
    }
    return { configured: true, authenticator: endpoint.host, secure: endpoint.secure === true };
  } catch (err) {
    cfg(env).logger?.warn?.('domainStatus failed', err);
    return { configured: null };
  }
}

/**
 * Stage 1: builds a challenge for the identifier and finds where to send the browser.
 *
 * The challenge asks for a POST callback, so the signed response travels in a request body and never
 * in a URL or a log. The manifest names the app for the authenticator's home-screen tile.
 *
 * @param env {object} - The Worker environment.
 * @param options {{identifier: string, callbackUrl: string, appHost: string}}
 * @returns {Promise<{ok: true, challenge: string, redirectUrl: string}|{ok: false, code: string, text: string}>}
 *          `challenge` is the stored form, which includes the key that decrypts the response.
 */
export async function startSignIn(env, { identifier, callbackUrl, appHost }) {
  const result = await Triauth.authenticate(
    { identifier, callbackUrl, ext: { callbackMethod: 'POST', manifest: { name: appHost } } },
    cfg(env),
  );
  if (result.error) {
    return failure(result.error.code);
  }
  return { ok: true, challenge: result.challenge, redirectUrl: result.redirectUrl };
}

/**
 * Stage 3: verifies the authenticator's response against the stored challenge and the user's DNS
 * records, then applies the bridge's own rules: the identity must be at this provider's domain, and
 * delegated sign-ins (another identity signing on the user's behalf) are not accepted.
 *
 * @param env {object} - The Worker environment.
 * @param options {{challenge: string, response: string, domain: string}}
 * @returns {Promise<{ok: true, claims: object, deviceTag: string}|{ok: false, code: string, text: string}>}
 *          `claims` are the token claims (see claimsOf); `deviceTag` names the device that signed,
 *          kept for a future refresh grant that would re-check it with Triauth.check.
 */
export async function finishSignIn(env, { challenge, response, domain }) {
  const result = await Triauth.authenticate({ challenge, response }, cfg(env));
  if (result.error) {
    return failure(result.error.code);
  }
  if (result.identifier.split('@')[1] !== domain) {
    return failure('domain');
  }
  if (result.actor) {
    return failure('delegated');
  }
  return { ok: true, claims: claimsOf(result), deviceTag: result.deviceTag };
}

/**
 * The claims the bridge puts into its tokens, from a verified sign-in. Every token carries all of
 * them, whatever scopes the app asked for: they are the identity's own public DNS data, and the user
 * approved the sign-in. The lookup code, the device tag, the device name, the session key, and the
 * keys never leave the bridge.
 *
 * @param result {object} - A successful Triauth.authenticate result.
 * @returns {object}
 */
export function claimsOf(result) {
  const claims = {
    sub: result.identifier,                          // the identifier is the stable account key
    email: result.identifier,
    email_verified: true,                            // whoever controls the domain's DNS controls both
    preferred_username: result.identifier,
    groups: result.groups,                           // e.g. ['admins@example.com'], from the groups records
    triauth_secure: result.secure === true,          // DNSSEC protected every record involved
    auth_time: Math.floor(result.verifiedAt / 1000), // when the bridge verified the response
  };
  if (typeof result.publicProfile?.name === 'string' && result.publicProfile.name !== '') {
    claims.name = result.publicProfile.name;
  }
  return claims;
}

/**
 * The texts shown on the sign-in page for the triauth error codes a sign-in can meet (triauth-js README,
 * "Error codes"), and for the bridge's own two rules. A validation error also carries a `reason`; the
 * bridge checks the username itself before stage 1, so one text per code is enough here.
 */
export const ERROR_TEXT = {
  dns_unavailable: 'DNS did not answer in time. Please try again.',
  invalid_identifier: 'This is not a valid username.',
  invalid_callback_url: 'This bridge cannot receive sign-ins at its current address. This is a configuration problem of the bridge, not of your identity.',
  domain_not_configured: 'This domain is not set up for triauth: it has no triauth DNS record.',
  verification_failed: 'The signed response could not be verified. Check that the username is yours and try again.',
  request_expired: 'The sign-in took too long and expired. Please try again.',
  request_denied: 'The sign-in was denied.',
  dnssec_required: 'This identity does not meet the DNSSEC requirement of this bridge.',
  domain: 'The identity that signed in is not at this domain.',
  delegated: 'Delegated sign-ins (another identity signing on your behalf) are not accepted here. Sign in with your own device.',
};

/**
 * The text for an error code, with a fallback that names the code.
 *
 * @param code {string} - A triauth error code, or 'domain' or 'delegated'.
 * @returns {string}
 */
export function errorText(code) {
  return Object.hasOwn(ERROR_TEXT, code) ? ERROR_TEXT[code] : `The sign-in failed (${code}). Please try again.`;
}

function failure(code) {
  return { ok: false, code, text: errorText(code) };
}

function cfg(env) {
  resolver ||= buildResolver();
  return { resolver, requireSecure: CONFIG.requireSecure, logger: makeLogger(env) };
}

function buildResolver() {
  const endpoints = Array.isArray(CONFIG.doh) ? CONFIG.doh : [CONFIG.doh];
  const resolvers = endpoints.map((url) => new Triauth.Resolvers.DnsJson(url, DNS_JSON_OPTIONS));
  return resolvers.length === 1
    ? resolvers[0]
    : new Triauth.Resolvers.MultiResolver(resolvers, { maxFailures: CONFIG.dohMaxFailures || 0 });
}

/**
 * A triauth-js logger that writes to the Worker log (`wrangler dev`, `wrangler tail`) when diagnostics
 * are on, or null (silent) otherwise. Each level goes to the console method of the same name, so a
 * routine DNS query shows as a debug line and only a real problem shows as an error.
 */
function makeLogger(env) {
  if (!CONFIG.debug && !env.DEBUG) {
    return null;
  }
  const line = (args) => '[triauth] ' + args.map(
    (a) => a && a.stack ? `${a}\n${a.stack}` : (typeof a === 'object' ? JSON.stringify(a) : String(a)),
  ).join(' ');
  return {
    debug: (...args) => console.debug(line(args)),
    info: (...args) => console.info(line(args)),
    warn: (...args) => console.warn(line(args)),
    error: (...args) => console.error(line(args)),
  };
}
