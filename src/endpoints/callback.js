/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// POST /{domain}/apps/{host}/callback?f=…: the authenticator's answer. triauth stage 3.
// GET  /{domain}/apps/{host}/: the app's address on the bridge, which the authenticator's tile opens:
//                              a page with a button to the app's host, for a host an app could have.
//
// Arrives:  a cross-site POST from the user's authenticator with the sealed, signed response, and the
//           browser's cookie for this sign-in (named by `f`).
// Checks:   the rate limit; the cookie opens the sign-in record (which deletes it, so the record is
//           single-use); the response verifies against the user's DNS records; the identity is at this
//           domain and signed in by itself; the app's options let it in (a client ID may limit sign-ins
//           to the members of one group).
// Stores:   one sealed code record (the request and the claims) for 60 seconds, under the code.
// Next:     the app's redirect URI with the code, by redirect or as a form post. A declined sign-in
//           goes back with access_denied. A failed one shows the sign-in page again.

import CONFIG from '../../config.js';
import { finishSignIn } from '../lib/triauth.js';
import { recordsOf } from '../lib/sealed.js';
import { returnUrl } from '../lib/request.js';
import { appHost, appRootUrl, parseClientId, refusalFor } from '../lib/credentials.js';
import { signInPage, errorPage, tilePage, formPostPage } from '../lib/pages.js';
import { readForm, parseCookies, withinRateLimit, cookie, redirect } from '../lib/http.js';
import { flowCookieName, usernameOf, FLOW_ID_LENGTH } from './login.js';
import { USERNAME_COOKIE } from './authorize.js';
import { tooManyRequests } from './domain.js';

export async function handle({ request, env, url, provider, params }) {
  if (!(await withinRateLimit(env.RATE_LIMIT_CALLBACK, request))) {
    return tooManyRequests();
  }
  const form = await readForm(request);
  if (!form) {
    return errorPage({ title: 'Request refused', text: 'The response could not be read.' });
  }

  // The sign-in record, by this browser's cookie for this sign-in. Taking it deletes it.
  const flowId = url.searchParams.get('f') || '';
  const hasFlowId = new RegExp(`^[A-Za-z0-9_-]{${FLOW_ID_LENGTH}}$`).test(flowId);
  const clearFlow = hasFlowId ? [cookie(flowCookieName(flowId), '', 0, 'None')] : [];
  const secret = hasFlowId ? parseCookies(request.headers.get('Cookie'))[flowCookieName(flowId)] : undefined;
  const record = secret ? await recordsOf(env, provider.domain).take('signin', secret) : null;
  if (!record || record.host !== params.host) {
    return errorPage({
      title: 'This sign-in has expired',
      text: 'The sign-in took too long, was already completed, or was started in another browser. Go back to the app and start again.',
      cookies: clearFlow,
    });
  }

  const { request: authorizationRequest, identifier } = record;
  const result = { state: authorizationRequest.state, iss: provider.issuer };

  // The user pressed Deny in the authenticator. They acted, so the browser may go back to the app.
  const response = form.get('response');
  if (response === 'false') {
    return returnToApp(authorizationRequest, { error: 'access_denied', error_description: 'The user declined the sign-in.', ...result }, clearFlow);
  }

  const again = (error, status) => signInPage({
    provider, request: authorizationRequest, host: record.host,
    username: usernameOf(identifier, provider.domain), error, status, cookies: clearFlow,
  });

  // Stage 3: verify the response against the challenge and the user's DNS records.
  const finished = await finishSignIn(env, { challenge: record.challenge, response: response ?? '', domain: provider.domain });
  if (!finished.ok) {
    return again(finished.text, 400);
  }

  // The app's options, from its client ID, which /login checked: a group limit, for example.
  const refusal = refusalFor(parseClientId(authorizationRequest.client_id), finished.claims, provider.domain);
  if (refusal) {
    return again(refusal, 403);
  }

  // The code: the app redeems it at /token within a minute, with its secret or its PKCE verifier.
  const code = await recordsOf(env, provider.domain).put('code', {
    client_id: authorizationRequest.client_id,
    redirect_uri: authorizationRequest.redirect_uri,
    code_challenge: authorizationRequest.code_challenge,
    nonce: authorizationRequest.nonce,
    scope: authorizationRequest.scope,
    claims: finished.claims,
    device: finished.deviceTag,   // a refresh checks this device in DNS again (token.js)
  }, CONFIG.lifetimes.code);

  const cookies = [...clearFlow];
  if (CONFIG.lifetimes.rememberUsername > 0) {
    cookies.push(cookie(USERNAME_COOKIE, identifier, CONFIG.lifetimes.rememberUsername, 'Lax'));
  }
  return returnToApp(authorizationRequest, { code, ...result }, cookies);
}

/**
 * Sends the browser back to the app with the result, the way the app asked for: a redirect
 * (response_mode=query) or a page that posts a form (response_mode=form_post).
 */
function returnToApp(authorizationRequest, fields, cookies) {
  const host = appHost(authorizationRequest.redirect_uri);
  if (authorizationRequest.response_mode === 'form_post') {
    return formPostPage({ action: authorizationRequest.redirect_uri, fields, host, cookies });
  }
  return redirect(returnUrl(authorizationRequest.redirect_uri, fields), cookies);
}

export function tile({ provider, params }) {
  const url = appRootUrl(params.host, provider.host);
  if (url === null) {
    return errorPage({ title: 'Not found', text: 'There is nothing at this address.', status: 404 });
  }
  return tilePage({ provider, host: params.host, url });
}
