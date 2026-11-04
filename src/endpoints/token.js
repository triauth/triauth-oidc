/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// POST /{domain}/token: the app's server trades a code, or a refresh token, for tokens.
//
// Arrives:  grant_type=authorization_code with the code, the redirect_uri, the app's credentials (as
//           HTTP Basic auth or form fields), and the PKCE code_verifier when the request had a
//           challenge; or grant_type=refresh_token with a refresh token and the credentials.
// Checks:   for a code: the client ID against the redirect URI, the secret against its fingerprint in
//           the client ID (or the PKCE verifier against the challenge), and that the code's record
//           names this client and this redirect URI. Taking the record deletes it: a code works once.
//           For a refresh: the secret, that the token was sealed by this bridge for this domain and
//           this app and has not expired, and that the device that signed in is still in DNS.
// Stores:   nothing.
// Next:     JSON with the ID token and the access token, both RS256 JWTs signed with the active key,
//           and a refresh token for an app with a secret that asked for offline_access (lib/refresh.js).

import CONFIG from '../../config.js';
import { Helpers } from 'triauth';
import { parseClientId, checkClient, checkSecret, refusalFor, redirectUriProblem, sameRedirectUri, SECRET_LENGTH } from '../lib/credentials.js';
import { recordsOf } from '../lib/sealed.js';
import { loadKeys } from '../lib/keys.js';
import { signJwt } from '../lib/jwt.js';
import { refreshGranted, grantedScope, mintRefreshToken, openRefreshToken } from '../lib/refresh.js';
import { checkSignIn } from '../lib/triauth.js';
import { readForm, json, withinRateLimit } from '../lib/http.js';

const CODE_VERIFIER_REGEXP = /^[A-Za-z0-9._~-]{43,128}$/;   // RFC 7636 §4.1
const RETRY_AFTER = { 'Retry-After': '60' };
const BASIC_CHALLENGE = { 'WWW-Authenticate': 'Basic realm="triauth-oidc"' };

export async function handle({ request, env, provider }) {
  if (!(await withinRateLimit(env.RATE_LIMIT_TOKEN, request))) {
    return oauthError('temporarily_unavailable', 'Too many requests from this address. Try again in a minute.', 429, RETRY_AFTER);
  }
  const form = await readForm(request);
  if (!form) {
    return oauthError('invalid_request', 'The body must be an application/x-www-form-urlencoded form.');
  }

  const auth = clientAuthentication(request, form);
  if (auth.error) {
    return oauthError('invalid_request', auth.error);
  }

  switch (form.get('grant_type')) {
    case 'authorization_code':
      return authorizationCodeGrant({ env, provider, form, auth });
    case 'refresh_token':
      return refreshTokenGrant({ env, provider, form, auth });
    default:
      return oauthError('unsupported_grant_type', 'Only grant_type=authorization_code and grant_type=refresh_token are supported.');
  }
}

/**
 * The authorization code grant (RFC 6749 §4.1.3, OpenID Connect Core §3.1.3).
 *
 * @param options {{env: object, provider: object, form: URLSearchParams, auth: {client_id: string, client_secret: (string|null), basic: boolean}}} -
 *        The Worker environment, the domain's provider (provider.js), the posted form, and the
 *        client's credentials from clientAuthentication.
 * @returns {Promise<Response>} The token response, with a refresh token for an app with a secret that
 *          asked for offline_access, or an OAuth error: `invalid_request` for a missing code or
 *          redirect_uri, `invalid_client` (401) for an unknown client ID or a wrong secret,
 *          `invalid_grant` for a code that is unknown, used, or bound to another client, redirect URI
 *          or PKCE challenge, and `server_error` (503) without a signing key.
 */
async function authorizationCodeGrant({ env, provider, form, auth }) {
  const code = form.get('code');
  const redirectUri = form.get('redirect_uri');
  const verifier = form.get('code_verifier');
  if (!code || !redirectUri) {
    return oauthError('invalid_request', 'The request needs code and redirect_uri.');
  }
  if (redirectUriProblem(redirectUri, provider.host)) {
    return oauthError('invalid_request', 'The redirect_uri is not one this bridge accepts.');
  }

  // The app: its client ID must have been made for this redirect URI, and it must prove its secret.
  if (!parseClientId(auth.client_id)) {
    return invalidClient('Unknown client_id.', auth);
  }
  const client = await checkClient(provider.domain, auth.client_id, redirectUri);
  if (!client) {
    return oauthError('invalid_grant', 'The client_id was not made for this redirect_uri.');
  }
  if (client.confidential && !(await checkSecret(client, auth.client_secret))) {
    return invalidClient('The client secret is wrong.', auth);
  }

  // The code: single-use, and bound to the client and the redirect URI of the sign-in.
  const record = await recordsOf(env, provider.domain).take('code', code);
  if (!record || record.client_id !== auth.client_id || !sameRedirectUri(record.redirect_uri, redirectUri)) {
    return oauthError('invalid_grant', 'The code is unknown, expired, already used, or was issued to another client or redirect_uri.');
  }

  // PKCE: the verifier must hash to the challenge the sign-in started with. A verifier without a
  // challenge, or a challenge without a verifier, fails, so PKCE can never be downgraded.
  if (record.code_challenge !== undefined || verifier !== null) {
    if (!record.code_challenge || !verifier || !CODE_VERIFIER_REGEXP.test(verifier) || await pkceHash(verifier) !== record.code_challenge) {
      return oauthError('invalid_grant', 'The PKCE code_verifier does not match the code_challenge of the sign-in.');
    }
  }

  const keys = await loadKeys(env);
  if (!keys.signing) {
    return noSigningKey();
  }

  // The session behind a refresh token, for an app with a secret that asked for offline_access.
  const now = Math.floor(Date.now() / 1000);
  const scope = grantedScope(record.scope, client);
  const cap = now + CONFIG.lifetimes.refreshMax;
  const session = refreshGranted(record.scope, client)
    ? { client_id: auth.client_id, scope, claims: record.claims, device: record.device, exp: Math.min(now + CONFIG.lifetimes.refreshIdle, cap), cap }
    : null;

  return issueTokens({ provider, keys, now, client_id: auth.client_id, scope, claims: record.claims, nonce: record.nonce, session });
}

/**
 * The refresh token grant (RFC 6749 §6, OpenID Connect Core §12). The app proves its secret, the
 * token must be one of ours for this domain and this app, and the device that signed in must still
 * be in DNS and the identity must still meet the app's options; then the tokens are reissued, the
 * ID token with the groups the identity has now and without a nonce, and the refresh token with its
 * expiry moved on.
 *
 * @param options {{env: object, provider: object, form: URLSearchParams, auth: {client_id: string, client_secret: (string|null), basic: boolean}}} -
 *        The Worker environment, the domain's provider (provider.js), the posted form, and the
 *        client's credentials from clientAuthentication.
 * @returns {Promise<Response>} The token response, or an OAuth error: `unsupported_grant_type` while
 *          the bridge issues no refresh tokens, `invalid_request` without a token, `invalid_client`
 *          (401) for an unknown client ID or a wrong secret, `unauthorized_client` for an app without
 *          a secret, `invalid_grant` for a token that is not ours, not this app's, expired, whose
 *          device has left DNS, or whose identity no longer meets the app's options, and
 *          `server_error` (503) without a signing key or when DNS could not be read, with a
 *          Retry-After so that the app tries again with the same token.
 */
async function refreshTokenGrant({ env, provider, form, auth }) {
  if (CONFIG.refreshTokens !== true) {
    return oauthError('unsupported_grant_type', 'This bridge issues no refresh tokens.');
  }
  const token = form.get('refresh_token');
  if (!token) {
    return oauthError('invalid_request', 'The request needs refresh_token.');
  }

  // The app: it must keep a secret, and prove it. No redirect URI travels with a refresh; the token
  // names the client ID it was issued to, and the secret's fingerprint is part of that ID.
  const client = parseClientId(auth.client_id);
  if (!client) {
    return invalidClient('Unknown client_id.', auth);
  }
  if (!client.confidential) {
    return oauthError('unauthorized_client', 'Apps without a secret get no refresh tokens, so this grant is not available to them.');
  }
  if (!(await checkSecret(client, auth.client_secret))) {
    return invalidClient('The client secret is wrong.', auth);
  }

  // The token: sealed by this bridge for this domain, issued to this app, and not expired. A scope
  // sent along is ignored: the claims never depended on it, and the response says what was granted.
  const keys = await loadKeys(env);
  if (!keys.signing) {
    return noSigningKey();
  }
  const session = await openRefreshToken(token, keys.published, provider.domain);
  const now = Math.floor(Date.now() / 1000);
  if (!session || session.client_id !== auth.client_id || now > session.exp) {
    return oauthError('invalid_grant', 'The refresh token is unknown, expired, or was issued to another client.');
  }

  // The identity: the device that signed in must still be published, with the groups it has now.
  const check = await checkSignIn(env, { identifier: session.claims.sub, deviceTag: session.device });
  if (!check.ok) {
    return check.final
      ? oauthError('invalid_grant', 'The device that signed in is no longer published for this identity, so the session has ended.')
      : oauthError('server_error', 'DNS could not be read right now. Try again in a moment.', 503, RETRY_AFTER);
  }

  // The app's options, as at the sign-in, against the groups of the day: a group limit ends the
  // session of someone who left the group.
  const claims = { ...session.claims, groups: check.groups, triauth_secure: check.secure };
  if (refusalFor(client, claims, provider.domain)) {
    return oauthError('invalid_grant', 'The identity no longer meets the conditions of this app, so the session has ended.');
  }

  return issueTokens({
    provider, keys, now, client_id: auth.client_id, scope: session.scope, claims,
    session: { ...session, exp: Math.min(now + CONFIG.lifetimes.refreshIdle, session.cap) },
  });
}

/**
 * The token response (RFC 6749 §5.1, OpenID Connect Core §3.1.3.3): the ID token, the access token,
 * and the refresh token when there is a session to seal into one. The identity's claims go first,
 * then the fixed ones, so that no claim can ever override iss, aud, or exp.
 *
 * @param options {{provider: object, keys: object, now: number, client_id: string, scope: string, claims: object, nonce?: string, session: (object|null)}}
 * @returns {Promise<Response>}
 */
async function issueTokens({ provider, keys, now, client_id, scope, claims, nonce, session }) {
  const { kid, privateKey } = keys.signing;
  const idToken = await signJwt({ typ: 'JWT', kid }, {
    ...claims,
    nonce,
    iss: provider.issuer,
    aud: client_id,
    iat: now,
    exp: now + CONFIG.lifetimes.idToken,
  }, privateKey);
  // The access token is for the bridge's own /userinfo only. Its `typ` and `aud` keep it from ever
  // passing for an ID token. It carries the claims, so /userinfo needs no storage.
  const accessToken = await signJwt({ typ: 'at+jwt', kid }, {
    ...claims,
    client_id,
    scope,
    jti: Helpers.randomString(22),
    iss: provider.issuer,
    aud: provider.userinfo,
    iat: now,
    exp: now + CONFIG.lifetimes.accessToken,
  }, privateKey);

  const response = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: CONFIG.lifetimes.accessToken,
    id_token: idToken,
    scope,
  };
  if (session) {
    response.refresh_token = await mintRefreshToken(keys.signing, provider.domain, session);
  }
  return json(response);
}

/**
 * Reads the client's credentials: HTTP Basic (client_secret_basic), or form fields
 * (client_secret_post), or just a client_id for an app without a secret. Basic credentials are split
 * at the colon, which neither a client ID nor a secret contains. Both parts are percent-decoded, as
 * RFC 6749 §2.3.1 asks (most apps skip the encoding, which decodes to itself).
 *
 * @returns {{client_id: string, client_secret: (string|null), basic: boolean}|{error: string}}
 */
export function clientAuthentication(request, form) {
  const header = request.headers.get('Authorization');
  const formId = form.get('client_id');
  const formSecret = form.get('client_secret');

  if (header) {
    const match = header.match(/^Basic\s+([A-Za-z0-9+/=]+)$/i);
    if (!match) {
      return { error: 'The Authorization header must be HTTP Basic.' };
    }
    if (formSecret !== null) {
      return { error: 'Send the client secret either as Basic auth or as a form field, not both.' };
    }
    let decoded;
    try {
      decoded = atob(match[1]);
    } catch {
      return { error: 'The Basic credentials are not base64.' };
    }
    const colon = decoded.lastIndexOf(':');
    if (colon < 1) {
      return { error: 'The Basic credentials must be client_id:client_secret.' };
    }
    try {
      const client_id = decodeURIComponent(decoded.slice(0, colon));
      const client_secret = decodeURIComponent(decoded.slice(colon + 1));
      if (formId !== null && formId !== client_id) {
        return { error: 'The client_id in the form differs from the one in the Authorization header.' };
      }
      return { client_id, client_secret, basic: true };
    } catch {
      return { error: 'The Basic credentials are not percent-encoded correctly.' };
    }
  }

  if (!formId) {
    return { error: 'The request has no client authentication: use Basic auth or send client_id (and client_secret).' };
  }
  return { client_id: formId, client_secret: formSecret, basic: false };
}

/**
 * An OAuth error response (RFC 6749 §5.2).
 */
export function oauthError(error, description, status = 400, headers = {}) {
  return json({ error, error_description: description }, status, headers);
}

/**
 * The 401 for a client that did not prove who it is. When it used HTTP Basic, the answer asks for it
 * again, as RFC 6749 §5.2 requires.
 */
function invalidClient(description, auth) {
  return oauthError('invalid_client', description, 401, auth.basic ? BASIC_CHALLENGE : {});
}

/**
 * The 503 for a bridge without a signing key, with a Retry-After, so that apps try again later.
 *
 * @returns {Response}
 */
function noSigningKey() {
  return oauthError('server_error', 'No signing key is configured on this bridge.', 503, RETRY_AFTER);
}

async function pkceHash(verifier) {
  return Helpers.arrayBufferToBase64Url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
}

export { SECRET_LENGTH };
