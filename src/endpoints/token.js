/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// POST /{domain}/token: the app's server trades the code for tokens.
//
// Arrives:  grant_type=authorization_code, the code, the redirect_uri, the app's credentials (as HTTP
//           Basic auth or form fields), and the PKCE code_verifier when the request had a challenge.
// Checks:   the client ID against the redirect URI, the secret against its fingerprint in the client
//           ID (or the PKCE verifier against the challenge), and that the code's record names this
//           client and this redirect URI. Taking the record deletes it: a code works once.
// Stores:   nothing.
// Next:     JSON with the ID token and the access token, both RS256 JWTs signed with the active key.
//
// Later: a refresh grant goes into the grant_type switch below. It would open a sealed refresh token
// (keys.js derives its key), re-check the device in DNS with Triauth.check, and reissue both tokens.

import CONFIG from '../../config.js';
import { Helpers } from 'triauth';
import { parseClientId, checkClient, checkSecret, redirectUriProblem, sameRedirectUri, SECRET_LENGTH } from '../lib/credentials.js';
import { recordsOf } from '../lib/sealed.js';
import { loadKeys } from '../lib/keys.js';
import { signJwt } from '../lib/jwt.js';
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
    default:
      return oauthError('unsupported_grant_type', 'Only grant_type=authorization_code is supported.');
  }
}

/**
 * The authorization code grant (RFC 6749 §4.1.3, OpenID Connect Core §3.1.3).
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
    return oauthError('server_error', 'No signing key is configured on this bridge.', 503, RETRY_AFTER);
  }

  const now = Math.floor(Date.now() / 1000);
  const { kid, privateKey } = keys.signing;
  // The identity's claims first, then the fixed ones, so that no claim can ever override iss, aud, or exp.
  const idToken = await signJwt({ typ: 'JWT', kid }, {
    ...record.claims,
    nonce: record.nonce,
    iss: provider.issuer,
    aud: auth.client_id,
    iat: now,
    exp: now + CONFIG.lifetimes.idToken,
  }, privateKey);
  // The access token is for the bridge's own /userinfo only. Its `typ` and `aud` keep it from ever
  // passing for an ID token. It carries the claims, so /userinfo needs no storage.
  const accessToken = await signJwt({ typ: 'at+jwt', kid }, {
    ...record.claims,
    client_id: auth.client_id,
    scope: record.scope,
    jti: Helpers.randomString(22),
    iss: provider.issuer,
    aud: provider.userinfo,
    iat: now,
    exp: now + CONFIG.lifetimes.accessToken,
  }, privateKey);

  return json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: CONFIG.lifetimes.accessToken,
    id_token: idToken,
    scope: record.scope,
  });
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

async function pkceHash(verifier) {
  return Helpers.arrayBufferToBase64Url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)));
}

export { SECRET_LENGTH };
