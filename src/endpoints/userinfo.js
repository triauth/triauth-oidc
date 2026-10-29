/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// GET or POST /{domain}/userinfo: the claims behind an access token.
//
// Arrives:  the access token, from the app's server: as `Authorization: Bearer`, or, from the few
//           apps that do it this way, as the `access_token` field of a posted form (RFC 6750 §2.2).
// Checks:   the token is one of ours: signed by a published key, typed at+jwt, issued by this
//           provider for this endpoint, and not expired.
// Stores:   nothing; the claims travel inside the token.
// Next:     the claims as JSON (OpenID Connect Core §5.3.2).

import { loadKeys } from '../lib/keys.js';
import { verifyJwt } from '../lib/jwt.js';
import { readForm, json } from '../lib/http.js';

const USERINFO_CLAIMS = ['sub', 'email', 'email_verified', 'preferred_username', 'name', 'groups', 'triauth_secure'];

export async function handle({ request, env, provider }) {
  const token = await accessTokenOf(request);
  if (!token) {
    return unauthorized('invalid_request', 'Send the access token as a Bearer token in the Authorization header.');
  }

  const keys = await loadKeys(env);
  const payload = await verifyJwt(token, { keys: keys.published, issuer: provider.issuer, audience: provider.userinfo, typ: 'at+jwt' });
  if (!payload) {
    return unauthorized('invalid_token', 'The access token is not valid for this endpoint.');
  }

  const claims = {};
  for (const name of USERINFO_CLAIMS) {
    if (payload[name] !== undefined) {
      claims[name] = payload[name];
    }
  }
  return json(claims);
}

/**
 * The access token of a request: the Bearer token of the Authorization header when there is one, or
 * else the access_token field of a posted form.
 *
 * @param request {Request} - The request.
 * @returns {Promise<string|null>} Null when there is none, or the header is not a Bearer token.
 */
async function accessTokenOf(request) {
  const header = request.headers.get('Authorization');
  if (header) {
    const match = header.match(/^Bearer\s+([A-Za-z0-9._~+/=-]+)$/i);
    return match ? match[1] : null;
  }
  if (request.method === 'POST') {
    const form = await readForm(request);
    return form?.get('access_token') || null;
  }
  return null;
}

function unauthorized(error, description) {
  return json({ error, error_description: description }, 401, {
    'WWW-Authenticate': `Bearer realm="triauth-oidc", error="${error}", error_description="${description}"`,
  });
}
