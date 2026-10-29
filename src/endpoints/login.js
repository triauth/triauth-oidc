/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// POST /{domain}/login: the user typed a username on the sign-in page. triauth stage 1.
//
// Arrives:  the sign-in page's form: the username, and the authorization request as hidden fields.
// Checks:   same origin, the rate limit, the authorization request again, the username's format.
// Stores:   one sealed sign-in record (the request and the triauth challenge) for 190 seconds, under
//           a secret that only this browser gets, as a cookie named after the sign-in.
// Next:     the user's authenticator, which was found in DNS. It will POST the signed response to
//           /{domain}/apps/{host}/callback?f={flowId}.

import CONFIG from '../../config.js';
import { validate } from 'triauth';
import { parseAuthorizationRequest } from '../lib/request.js';
import { startSignIn } from '../lib/triauth.js';
import { recordsOf } from '../lib/sealed.js';
import { signInPage, errorPage } from '../lib/pages.js';
import { readForm, sameOrigin, withinRateLimit, randomId, cookie, redirect } from '../lib/http.js';
import { requestErrorPage } from './authorize.js';
import { tooManyRequests } from './domain.js';

export const FLOW_ID_LENGTH = 16;   // base64url characters, 12 random bytes

export async function handle({ request, env, provider }) {
  if (!sameOrigin(request, provider.origin)) {
    return errorPage({ title: 'Request refused', text: 'The sign-in form must be sent from the bridge\'s own page.', status: 403 });
  }
  if (!(await withinRateLimit(env.RATE_LIMIT_LOGIN, request))) {
    return tooManyRequests();
  }
  const form = await readForm(request);
  if (!form) {
    return errorPage({ title: 'Request refused', text: 'The form could not be read.' });
  }

  // The request comes back from the page as hidden fields, and is checked exactly as at /authorize.
  const parsed = await parseAuthorizationRequest(form, provider);
  if (!parsed.ok) {
    return requestErrorPage(provider, parsed);
  }
  const { request: authorizationRequest, client } = parsed;
  const again = (error) => signInPage({ provider, request: authorizationRequest, host: client.host, username, error, status: 400 });

  // The identifier: the typed username, lowercased, at this domain. A full identifier at this domain is fine too.
  const username = usernameOf(form.get('username') || '', provider.domain);
  const identifier = `${username}@${provider.domain}`;
  if (username === '' || !validate({ identifier }).valid) {
    return again(`Type only the part before @${provider.domain}.`);
  }

  // Stage 1: triauth builds the challenge and finds the authenticator in DNS.
  const flowId = randomId(12);
  const started = await startSignIn(env, { identifier, callbackUrl: provider.callback(client.host, flowId), appHost: client.host });
  if (!started.ok) {
    return again(started.text);
  }

  // The record holds everything the callback needs; its secret goes to this browser only.
  const secret = await recordsOf(env, provider.domain).put('signin', {
    request: authorizationRequest,
    host: client.host,
    identifier,
    challenge: started.challenge,
  }, CONFIG.lifetimes.signIn);

  return redirect(started.redirectUrl, [cookie(flowCookieName(flowId), secret, CONFIG.lifetimes.signIn, 'None')]);
}

/**
 * The cookie that carries one sign-in's secret. One cookie per sign-in, so that sign-ins in several
 * tabs do not disturb each other. SameSite=None, because the authenticator's callback is a cross-site POST.
 */
export function flowCookieName(flowId) {
  return `__Host-triauth_f_${flowId}`;
}

/**
 * The username from what was typed: ASCII-lowercased, trimmed, with '@domain' removed when it is this domain.
 */
export function usernameOf(typed, domain) {
  const lower = typed.trim().replace(/[A-Z]/g, (c) => c.toLowerCase());
  return lower.endsWith('@' + domain) ? lower.slice(0, -domain.length - 1) : lower;
}
