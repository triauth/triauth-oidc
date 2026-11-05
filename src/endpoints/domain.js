/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// GET /{domain}/  and  POST /{domain}/credentials: the admin's page.
//
// Arrives:  an admin who sets an app up, or the credentials form with one to three redirect URIs.
// Checks:   the domain's triauth DNS record (to show its status), each redirect URI's rules (stricter
//           for an app without a secret), and the group's name when the app is limited to one group.
// Stores:   nothing. The credentials are computed and shown once.
// Next:     the page with the settings to copy, or the credentials page.

import { createCredentials, redirectUriProblem, publicClientProblem, groupNameProblem } from '../lib/credentials.js';
import { domainStatus } from '../lib/triauth.js';
import { domainPage, credentialsPage, errorPage } from '../lib/pages.js';
import { readForm, sameOrigin, withinRateLimit } from '../lib/http.js';

// The form's redirect URI fields, in order. The first is required; the view shows the other two
// behind an "Add another redirect URI" line each (views/domain.js names the same fields).
const REDIRECT_URI_FIELDS = ['redirect_uri', 'redirect_uri_2', 'redirect_uri_3'];

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

  const redirectUris = REDIRECT_URI_FIELDS.map((name) => (form.get(name) || '').trim());
  const publicClient = form.get('public') === '1';
  const limitGroup = form.get('limit_group') === '1';
  const group = groupOf(form.get('group') || '', provider.domain);
  const problems = redirectUris.map((uri, i) => (i > 0 && uri === '' ? null : redirectUriProblem(uri, provider.host) ?? (publicClient ? publicClientProblem(uri) : null)));
  const invalid = problems.findIndex(Boolean);
  const problem = invalid >= 0 ? problems[invalid] : limitGroup ? groupNameProblem(group, provider.domain) : null;
  if (problem) {
    return domainPage({ provider, form: { redirectUris, invalid: invalid >= 0 ? invalid : null, publicClient, limitGroup, group, problem }, httpStatus: 400 });
  }

  const created = await createCredentials(provider.domain, redirectUris.filter(Boolean), { secret: !publicClient, group: limitGroup ? group : null });
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
