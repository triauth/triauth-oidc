/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// GET /{domain}/.well-known/openid-configuration  and  GET /{domain}/jwks
//
// Arrives:  an app that was given the issuer and looks up the provider's endpoints and keys. The
//           router also brings the RFC 8414 spellings here (/.well-known/openid-configuration/{domain},
//           and the oauth-authorization-server name); the document is the same.
// Checks:   nothing; both documents are fixed per domain.
// Stores:   nothing.
// Next:     JSON. Apps cache both; the cache headers say for how long.

import CONFIG from '../../config.js';
import { publishedJwks } from '../lib/keys.js';
import { json } from '../lib/http.js';

const CACHE = { 'Cache-Control': 'public, max-age=300' };

/**
 * The provider's discovery document (OpenID Connect Discovery 1.0). Apps read the endpoint URLs and
 * the capabilities from it, so what is listed here is what the bridge supports and nothing more:
 * the refresh grant and the offline_access scope only while the bridge issues refresh tokens.
 */
export function configuration({ provider }) {
  const refresh = CONFIG.refreshTokens === true;
  return json({
    issuer: provider.issuer,
    authorization_endpoint: provider.authorize,
    token_endpoint: provider.token,
    userinfo_endpoint: provider.userinfo,
    jwks_uri: provider.jwks,
    response_types_supported: ['code'],
    response_modes_supported: ['query', 'form_post'],
    grant_types_supported: refresh ? ['authorization_code', 'refresh_token'] : ['authorization_code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    code_challenge_methods_supported: ['S256'],
    scopes_supported: ['openid', 'email', 'profile', 'groups', ...(refresh ? ['offline_access'] : [])],
    claims_supported: ['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'email', 'email_verified', 'preferred_username', 'name', 'groups', 'triauth_secure'],
    claims_parameter_supported: false,
    request_parameter_supported: false,
    request_uri_parameter_supported: false,
    authorization_response_iss_parameter_supported: true,
    service_documentation: 'https://www.triauth.org/',
  }, 200, CACHE);
}

/**
 * The public keys of every filled slot, which apps use to check token signatures (RFC 7517).
 */
export async function jwks({ env }) {
  const keys = await publishedJwks(env);
  if (keys.keys.length === 0) {
    return json({ error: 'server_error', error_description: 'No signing key is configured on this bridge.' }, 503, { 'Retry-After': '60' });
  }
  return json(keys, 200, CACHE);
}
