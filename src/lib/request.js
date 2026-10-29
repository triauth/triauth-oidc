/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// The authorization request.
//
// A sign-in starts when an app sends the browser to /authorize with a handful of parameters. This
// file reads and checks them: once at /authorize, to show the sign-in page, and again at /login, where
// the page brings them back as hidden fields. The names are the OAuth and OpenID Connect names, kept
// as they are so that the code reads next to the specifications:
//
//   client_id              which app asks; the ID binds the redirect URI (credentials.js)
//   redirect_uri           where the browser goes back with the code
//   response_type          "code", the only flow the bridge offers
//   scope                  what the app asks to learn; the bridge returns every claim regardless
//   state                  the app's own token, returned untouched; the app uses it against CSRF
//   nonce                  the app's own token, returned inside the ID token, against token replay
//   code_challenge         PKCE: the hash of a secret that the app proves at /token (S256 only)
//   response_mode          "query" (a redirect) or "form_post" (the result as a form submission)
//   login_hint             a username or identifier to prefill
//   prompt                 "none" asks for a silent sign-in, which a bridge without sessions cannot do
//
// A request that fails before its client ID and redirect URI are confirmed gets an error page and no
// way back, because the bridge does not know where "back" is. After that point, the error page offers
// a link back to the app that carries the error, as OAuth describes, but the bridge never redirects
// on its own: anyone can make a client ID for any URL, so an automatic redirect would make the bridge
// an open redirector (RFC 9700 §4.11).

import { Helpers, validate } from 'triauth';
import { checkClient, redirectUriProblem, publicClientProblem } from './credentials.js';

/** The fields that travel through a sign-in: hidden fields on the page, then the code's record. */
export const CARRIED = ['response_type', 'client_id', 'redirect_uri', 'scope', 'state', 'nonce', 'code_challenge', 'code_challenge_method', 'response_mode'];

const LIMITS = { client_id: 512, redirect_uri: 2048, response_type: 64, scope: 1024, state: 4096, nonce: 1024,
  code_challenge: 128, code_challenge_method: 16, response_mode: 32, login_hint: 256, prompt: 128 };

const SCOPE_REGEXP = /^[\x21\x23-\x5B\x5D-\x7E]+( [\x21\x23-\x5B\x5D-\x7E]+)*$/;   // RFC 6749 §3.3
const CODE_CHALLENGE_REGEXP = /^[A-Za-z0-9._~-]{43,128}$/;                          // RFC 7636 §4.2

/**
 * Reads and checks an authorization request.
 *
 * @param params {URLSearchParams} - The query of /authorize, or the form posted to /authorize or /login.
 * @param provider {object} - The domain's provider (provider.js).
 * @returns {Promise<
 *     {ok: true, request: object, client: object}
 *   | {ok: false, error: string, description: string, returnTo: ({redirect_uri: string, state: (string|undefined), response_mode: string}|null)}
 * >} On success, `request` holds the CARRIED fields plus `login_hint` (a username, when usable) and
 *    `client` is the parsed client from credentials.js. On failure, `error` is the OAuth error code,
 *    `description` a sentence for humans, and `returnTo` where and how the error page may offer a way
 *    back (a link for `query`, a form for `form_post`), or null when the client ID or the redirect URI
 *    did not check out.
 */
export async function parseAuthorizationRequest(params, provider) {
  try {
    return await parse(params, provider);
  } catch (err) {
    if (err instanceof ParameterError) {
      return fail('invalid_request', err.message);
    }
    throw err;
  }
}

function fail(error, description, returnTo = null) {
  return { ok: false, error, description, returnTo };
}

class ParameterError extends Error {}

async function parse(params, provider) {
  const value = reader(params);

  // 1. The app: the client ID must have been made for this domain and this redirect URI.
  const client_id = value('client_id');
  const redirect_uri = value('redirect_uri');
  if (!client_id) {
    return fail('invalid_request', 'The request has no client_id.');
  }
  if (!redirect_uri) {
    return fail('invalid_request', 'The request has no redirect_uri.');
  }
  const uriProblem = redirectUriProblem(redirect_uri, provider.host);
  if (uriProblem) {
    return fail('invalid_request', `The redirect_uri is not acceptable. ${uriProblem}`);
  }
  const client = await checkClient(provider.domain, client_id, redirect_uri);
  if (!client) {
    return fail('invalid_request', `The client_id was not made for ${provider.domain} and this redirect_uri. Create credentials for the app at ${provider.page} and use exactly the redirect URI they were made for.`);
  }

  // 2. From here on, the bridge knows the app, so an error may offer a way back to it: a link, or a
  //    form when the app asked for form_post. The mode is read here and checked further down.
  const state = value('state');
  const response_mode = value('response_mode') ?? 'query';
  const returnTo = { redirect_uri, state, response_mode: response_mode === 'form_post' ? 'form_post' : 'query' };

  if (value('response_type') !== 'code') {
    return fail('unsupported_response_type', 'Only response_type=code is supported.', returnTo);
  }

  const scope = value('scope') ?? 'openid';
  if (!SCOPE_REGEXP.test(scope)) {
    return fail('invalid_scope', 'The scope is not a space-separated list of scope tokens.', returnTo);
  }

  const nonce = value('nonce');

  const code_challenge = value('code_challenge');
  const code_challenge_method = value('code_challenge_method');
  if (code_challenge !== undefined && !CODE_CHALLENGE_REGEXP.test(code_challenge)) {
    return fail('invalid_request', 'The code_challenge is not a valid PKCE challenge.', returnTo);
  }
  if ((code_challenge !== undefined || code_challenge_method !== undefined) && code_challenge_method !== 'S256') {
    return fail('invalid_request', 'PKCE needs code_challenge_method=S256; "plain" is not supported.', returnTo);
  }
  if (code_challenge === undefined && code_challenge_method !== undefined) {
    return fail('invalid_request', 'A code_challenge_method without a code_challenge.', returnTo);
  }
  const publicProblem = client.confidential ? null : publicClientProblem(redirect_uri);
  if (publicProblem) {
    return fail('unauthorized_client', publicProblem, returnTo);
  }
  if (!client.confidential && code_challenge === undefined) {
    return fail('invalid_request', 'This client has no secret, so it must use PKCE: send a code_challenge.', returnTo);
  }

  if (response_mode !== 'query' && response_mode !== 'form_post') {
    return fail('invalid_request', 'Only response_mode=query and response_mode=form_post are supported.', returnTo);
  }

  if ((value('prompt') ?? '').split(' ').includes('none')) {
    return fail('login_required', 'This provider keeps no session, so it cannot sign in without the user.', returnTo);
  }
  if (params.has('request')) {
    return fail('request_not_supported', 'Request objects are not supported.', returnTo);
  }
  if (params.has('request_uri')) {
    return fail('request_uri_not_supported', 'Request URIs are not supported.', returnTo);
  }

  return {
    ok: true,
    client,
    request: {
      response_type: 'code',
      client_id,
      redirect_uri,
      scope,
      state,
      nonce,
      code_challenge,
      code_challenge_method: code_challenge === undefined ? undefined : 'S256',
      response_mode,
      login_hint: usableLoginHint(value('login_hint'), provider.domain),
    },
  };
}

/**
 * The hidden fields that carry a request through the sign-in page.
 *
 * @param request {object} - A request from parseAuthorizationRequest.
 * @returns {Array<[string, string]>} Name and value pairs, only for the fields the request has.
 */
export function carriedFields(request) {
  return CARRIED.filter((name) => request[name] !== undefined).map((name) => [name, request[name]]);
}

/**
 * The URL that sends the browser back to the app: the redirect URI with the given parameters added.
 * A redirect URI may have a query of its own, which stays.
 *
 * @param redirectUri {string} - The app's redirect URI.
 * @param params {object} - The parameters; undefined values are skipped.
 * @returns {string}
 */
export function returnUrl(redirectUri, params) {
  const query = new URLSearchParams();
  for (const [name, value] of Object.entries(params)) {
    if (value !== undefined) {
      query.set(name, value);
    }
  }
  return redirectUri + (redirectUri.includes('?') ? '&' : '?') + query.toString();
}

/**
 * The prefill from a login_hint: the username when the hint is a username, or an identifier at this
 * domain; nothing otherwise.
 */
function usableLoginHint(hint, domain) {
  if (hint === undefined) {
    return undefined;
  }
  const lower = Helpers.asciiLowercase(hint.trim());
  const username = lower.endsWith('@' + domain) ? lower.slice(0, -domain.length - 1) : lower;
  return !username.includes('@') && validate({ identifier: `${username}@${domain}` }).valid ? username : undefined;
}

/**
 * A reader over the parameters that enforces "each at most once" and the size limits.
 */
function reader(params) {
  return (name) => {
    const values = params.getAll(name);
    if (values.length > 1) {
      throw new ParameterError(`The parameter ${name} appears more than once.`);
    }
    if (values.length === 1 && values[0].length > LIMITS[name]) {
      throw new ParameterError(`The parameter ${name} is too long.`);
    }
    return values[0];
  };
}
