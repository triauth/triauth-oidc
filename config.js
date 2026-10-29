/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// Every knob of the bridge, in one place. Edit and `wrangler deploy`.
// Secrets and per-deployment variables live in wrangler.jsonc instead.

export default {

  // Reject identities whose DNS records are not DNSSEC-authenticated (triauth error 404).
  // Off by default: many domains have no DNSSEC yet, and every token reports the DNSSEC
  // result in its `triauth_secure` claim, so apps can decide for themselves.
  requireSecure: false,

  // DNS-over-HTTPS endpoints (JSON API) for all DNS resolution. With two or more, every answer
  // is cross-validated: a record counts only when ALL endpoints return it, so one rogue,
  // compromised, or hijacked provider can neither forge keys nor hide a revocation.
  doh: ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'],

  // How many DoH endpoints may fail (transport error) while resolution still succeeds.
  // 0 = strict: every endpoint must answer, and an endpoint outage blocks sign-ins until it recovers.
  dohMaxFailures: 0,

  // Lifetimes, in seconds.
  lifetimes: {
    // The sign-in record, from the redirect to the authenticator until the user approves. triauth
    // gives the user 180 s plus the library's 5 s clock-drift allowance, so the record outlives
    // every response the protocol would still accept.
    signIn: 190,
    // The authorization code, from the redirect back to the app until the app redeems it.
    // Apps redeem within a second; 60 s covers slow ones. Codes are single-use anyway.
    code: 60,
    // The ID token. Apps consume it at once; a short life limits replay at apps that skip checks.
    idToken: 600,
    // The access token, which works only at this bridge's /userinfo endpoint.
    accessToken: 3600,
    // The cookie that remembers the last username in the browser. 0 disables it.
    rememberUsername: 30 * 86400,
  },

  // How often a domain's Store purges expired records, in seconds. Records are deleted when
  // taken, so the purge only collects sign-ins that were never completed.
  purgeInterval: 300,

  // Log protocol diagnostics (visible in `wrangler dev` and `wrangler tail`).
  // The DEBUG variable in wrangler.jsonc turns this on without editing code.
  debug: false,
};
