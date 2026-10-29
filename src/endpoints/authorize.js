/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// GET or POST /{domain}/authorize: an app sends the browser here to sign someone in.
//
// Arrives:  the app's authorization request (client_id, redirect_uri, state, nonce, …), by redirect.
// Checks:   every parameter (lib/request.js), above all that the client ID was made for this redirect URI.
// Stores:   nothing yet. The request rides along the sign-in page as hidden fields.
// Next:     the sign-in page, or an error page with a way back to the app when the app is known.

import { parseAuthorizationRequest, returnUrl } from '../lib/request.js';
import { appHost } from '../lib/credentials.js';
import { signInPage, errorPage } from '../lib/pages.js';
import { readForm, parseCookies, methodNotAllowed } from '../lib/http.js';

export const USERNAME_COOKIE = '__Host-triauth_user';

export async function handle({ request, url, provider }) {
  let params;
  if (request.method === 'GET') {
    params = url.searchParams;
  } else if (request.method === 'POST') {
    params = await readForm(request);
    if (!params) {
      return errorPage({ title: 'This sign-in request cannot be used', text: 'The request body could not be read as a form.' });
    }
  } else {
    return methodNotAllowed(['GET', 'POST']);
  }

  const parsed = await parseAuthorizationRequest(params, provider);
  if (!parsed.ok) {
    return requestErrorPage(provider, parsed);
  }

  return signInPage({
    provider,
    request: parsed.request,
    host: parsed.client.host,
    username: parsed.request.login_hint ?? rememberedUsername(request, provider.domain),
  });
}

/**
 * The error page for a request that failed its checks. When the app is known (its client ID checked
 * out against its redirect URI), the page offers a way back that carries the error as OAuth describes:
 * a link for response_mode=query, a form for response_mode=form_post. Either way the user presses the
 * button; the bridge itself never redirects before the user acts.
 *
 * @param provider {object} - The domain's provider.
 * @param failure {{error: string, description: string, returnTo: (object|null)}} - From parseAuthorizationRequest.
 * @returns {Response}
 */
export function requestErrorPage(provider, failure) {
  let returnTo = null;
  if (failure.returnTo) {
    const { redirect_uri, state, response_mode } = failure.returnTo;
    const fields = { error: failure.error, error_description: failure.description, state, iss: provider.issuer };
    returnTo = response_mode === 'form_post'
      ? { host: appHost(redirect_uri), action: redirect_uri, fields }
      : { host: appHost(redirect_uri), url: returnUrl(redirect_uri, fields) };
  }
  return errorPage({ title: 'This sign-in request cannot be used', text: failure.description, returnTo });
}

/**
 * The username remembered in this browser (set after a successful sign-in), when it is at this domain.
 */
export function rememberedUsername(request, domain) {
  const remembered = parseCookies(request.headers.get('Cookie'))[USERNAME_COOKIE];
  return remembered && remembered.endsWith('@' + domain) ? remembered.slice(0, -domain.length - 1) : '';
}
