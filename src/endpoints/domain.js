/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// GET /{domain}/  and  POST /{domain}/credentials: the admin's page.
//
// Arrives:  an admin who sets an app up, or the credentials form with a redirect URI.
// Checks:   the domain's triauth DNS record (to show its status), the redirect URI's rules (stricter
//           for an app without a secret), and the group's name when the app is limited to one group.
// Stores:   nothing. The credentials are computed and shown once.
// Next:     the page with the settings to copy, or the credentials page.

import { createCredentials, redirectUriProblem, publicClientProblem, groupNameProblem } from '../lib/credentials.js';
import { domainStatus } from '../lib/triauth.js';
import { domainPage, credentialsPage, errorPage } from '../lib/pages.js';
import { readForm, sameOrigin, withinRateLimit } from '../lib/http.js';

export async function page({ request, env, provider }) {
  if (!(await withinRateLimit(env.RATE_LIMIT_PAGES, request))) {
    return tooManyRequests();
  }
  return domainPage({ provider, status: await domainStatus(env, provider.domain) });
}

export async function credentials({ request, env, provider }) {
  if (!sameOrigin(request, provider.origin)) {
    return errorPage({ title: 'Request refused', text: 'This form must be sent from the bridge\'s own page.', status: 403 });
  }
  const form = await readForm(request);
  if (!form) {
    return errorPage({ title: 'Request refused', text: 'The form could not be read.', status: 400 });
  }

  const redirectUri = (form.get('redirect_uri') || '').trim();
  const publicClient = form.get('public') === '1';
  const limitGroup = form.get('limit_group') === '1';
  const group = groupOf(form.get('group') || '', provider.domain);
  const problem = redirectUriProblem(redirectUri, provider.host)
    ?? (publicClient ? publicClientProblem(redirectUri) : null)
    ?? (limitGroup ? groupNameProblem(group, provider.domain) : null);
  if (problem) {
    return domainPage({ provider, form: { redirectUri, publicClient, limitGroup, group, problem }, httpStatus: 400 });
  }

  const created = await createCredentials(provider.domain, redirectUri, { secret: !publicClient, group: limitGroup ? group : null });
  return credentialsPage({ provider, credentials: created });
}

/**
 * The group's name from what was typed: ASCII-lowercased, trimmed, with '@domain' removed when it is
 * this domain, as the username field on the sign-in page does.
 */
function groupOf(typed, domain) {
  const lower = typed.trim().replace(/[A-Z]/g, (c) => c.toLowerCase());
  return lower.endsWith('@' + domain) ? lower.slice(0, -domain.length - 1) : lower;
}

export function tooManyRequests() {
  const response = errorPage({ title: 'Too many requests', text: 'Please wait a minute and try again.', status: 429 });
  response.headers.set('Retry-After', '60');
  return response;
}
