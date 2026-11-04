/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// Refresh tokens.
//
// An app that keeps a secret and asks for the `offline_access` scope gets a refresh token with its
// code: a credential it trades at /token for fresh tokens, without the user, for as long as the
// identity's records stay in DNS. The bridge keeps no record of the tokens it issued. A refresh
// token is a sealed record (sealed.js) that travels instead of being stored: it carries everything a
// refresh needs, under a secret derived from a signing key slot (keys.js), and it names the slot, so
// that a token outlives a key rotation but not the deletion of a leaked key.
//
//   client_id   the app, which authenticates at a refresh as at the code exchange
//   scope       what the app was granted
//   claims      the claims of the sign-in (triauth.js); a refresh replaces the groups and the DNSSEC
//               result with what DNS says now, and keeps the rest, auth_time and name included
//   device      the device tag of the sign-in, which every refresh checks in DNS
//   exp         when this token expires, in seconds; a refresh issues a successor that lasts
//               lifetimes.refreshIdle again
//   cap         when the session ends for good: the sign-in plus lifetimes.refreshMax, the same in
//               every successor, and never before exp
//
// Every refresh issues a new token, and the old one stays valid until its own expiry: there is no
// list to strike it from. Access ends where triauth ends it, by removing the device's key from DNS,
// which the next refresh sees. Apps without a secret get no refresh token: a stolen token of theirs
// could be told from the app's own only by remembering every token issued (RFC 9700 §4.14), and the
// bridge remembers none. `refreshTokens` in config.js turns the feature off for a whole bridge.

import CONFIG from '../../config.js';
import { seal, open } from './sealed.js';

const OFFLINE_ACCESS = 'offline_access';
const KIND = 'refresh';

/**
 * Whether a sign-in gets a refresh token: the bridge issues them, the app keeps a secret, and it
 * asked for offline_access.
 *
 * @param scope {string} - The request's scope.
 * @param client {{confidential: boolean}} - The parsed client (credentials.js).
 * @returns {boolean}
 */
export function refreshGranted(scope, client) {
  return CONFIG.refreshTokens === true && client.confidential && words(scope).includes(OFFLINE_ACCESS);
}

/**
 * The scope the bridge grants: the request's, without offline_access when no refresh token comes
 * with it, so that the token response says what the app got (RFC 6749 §5.1).
 *
 * @param scope {string} - The request's scope.
 * @param client {{confidential: boolean}} - The parsed client.
 * @returns {string}
 */
export function grantedScope(scope, client) {
  return refreshGranted(scope, client) ? scope : words(scope).filter((word) => word !== OFFLINE_ACCESS).join(' ');
}

/**
 * Seals a session into a refresh token.
 *
 * @param slot {{slot: string, sealingSecret: string}} - The signing slot that seals, from keys.js.
 * @param domain {string} - The provider's domain, bound into the seal.
 * @param session {object} - The fields listed above.
 * @returns {Promise<string>} The token: the slot's name, then the sealed record.
 */
export async function mintRefreshToken(slot, domain, session) {
  const { blob } = await seal(slot.sealingSecret, { kind: KIND, domain }, session);
  return `${slot.slot}.${blob}`;
}

/**
 * Opens a refresh token.
 *
 * @param token {*} - The token as the app sent it.
 * @param slots {Array<{slot: string, sealingSecret: string}>} - The published slots, from keys.js.
 * @param domain {string} - The provider's domain it must have been sealed for.
 * @returns {Promise<object|null>} The session, or null when the token is not one of this bridge's
 *          for this domain, or its slot is gone.
 */
export async function openRefreshToken(token, slots, domain) {
  const parts = String(token).split('.');
  const slot = parts.length === 3 ? slots.find((candidate) => candidate.slot === parts[0]) : undefined;
  if (!slot) {
    return null;
  }
  const session = await open(slot.sealingSecret, { kind: KIND, domain }, `${parts[1]}.${parts[2]}`);
  return isSession(session) ? session : null;
}

/**
 * The words of a scope.
 *
 * @param scope {*} - A space-separated scope, or nothing.
 * @returns {Array<string>}
 */
function words(scope) {
  return String(scope ?? '').split(' ').filter(Boolean);
}

/**
 * Whether an opened record is a session as mintRefreshToken seals them: every field present and of
 * its type. The seal already proves the record is ours; this keeps the grant from acting on a record
 * of another shape, such as one an older version of the bridge sealed.
 *
 * @param value {*} - What open returned.
 * @returns {boolean}
 */
function isSession(value) {
  return value !== null && typeof value === 'object'
    && typeof value.client_id === 'string' && typeof value.scope === 'string' && typeof value.device === 'string'
    && typeof value.claims?.sub === 'string'
    && Number.isFinite(value.exp) && Number.isFinite(value.cap);
}
