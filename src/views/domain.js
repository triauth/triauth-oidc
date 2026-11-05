/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// A domain's page, laid out like a settings dashboard: the domain with its status, the card that
// connects an app (the reason most admins are here), and one quiet fold below it, closed: the
// provider settings.
//
//   provider   the domain's provider, with its URLs
//   status     {configured: true, authenticator, secure} | {configured: false} | {configured: null}
//              when DNS could not be read, or null when the page shows no status
//   form       {redirectUris, invalid, publicClient, limitGroup, group, problem}: the form as it was
//              sent back, with the problem found in it and the index of the redirect URI the problem
//              is about (null when it is not about one), or {} for a fresh form
//
// The card walks someone new to OpenID Connect through the order that is easy to miss: copy the
// redirect URI out of the app, paste it here, then copy what comes back into the app. The steps sit
// above the fields, not beside them, so the card reads in that order and a long redirect URI fits its
// field, where it can be checked against the app's. A hint line under the first step links the
// showcase on www.triauth.org, filtered to the apps that sign in through the bridge, where each app's
// guide shows where its redirect URI is; the bridge keeps no list of guides of its own. The group's
// field shows only while its box is checked, by the stylesheet alone, because the pages run no
// scripts; the second and third redirect URI fields appear the same way, behind an "Add another
// redirect URI" line each (redirectUriFields, below). The box's hint links to triauth's page on
// groups, which many admins meet here first. The
// hint sits outside the label, tied to the box by aria-describedby, so the link is not read as part
// of the box's name. Both links open in a new tab, so the form keeps what was typed.
//
// The notice next to the Connect button is how the person connecting an app agrees to the Terms
// (the Terms name "clicking a button that refers to them"). It sits right next to the button, in
// readable text, and links both documents.

import { html } from '../lib/html.js';
import { breakAfterDots, providerSettings, TERMS_URL, PRIVACY_URL, EVERYWHERE_URL } from './partials.js';

export default ({ provider, status, form }) => html`
<div class="page-head">
<h1>OpenID Connect for ${breakAfterDots(provider.domain)}</h1>
</div>
${banner(provider.domain, status)}
<form class="card" method="post" action="${provider.credentials}">
<div class="card-head">
<h2>Connect an app</h2>
<p>Let everyone with an <strong>@${provider.domain}</strong> identity sign in to an app with triauth.</p>
<ol>
<li>Go to the app's SSO, OpenID Connect (OIDC), or generic OAuth settings, and copy its redirect URI. <span class="hint">Not sure where? <a href="${EVERYWHERE_URL}?q=OIDC" target="_blank" rel="noopener">Setup guides for popular apps <span aria-hidden="true">↗</span></a></span></li>
<li>Paste it below and click <strong>Connect app</strong>.</li>
<li>Put the client ID, secret and issuer you get back into the app.</li>
</ol>
</div>
<div class="card-body">
${form.problem ? html`<p class="err">${form.problem}</p>` : ''}
${redirectUriFields(form)}
<div class="check"><input id="public" type="checkbox" name="public" value="1" ${form.publicClient ? 'checked' : ''}> <label for="public">This app can't keep a secret <span class="hint">For command-line and mobile apps.</span></label></div>
<div class="check"><input id="limit_group" type="checkbox" name="limit_group" value="1" aria-describedby="limit_group_hint" ${form.limitGroup ? 'checked' : ''}> <div>
<label for="limit_group">Limit sign-ins to a specific group</label>
<p id="limit_group_hint" class="hint">Only the group's members can sign in to the app. <a href="https://www.triauth.org/identity/groups" target="_blank" rel="noopener">How groups work <span aria-hidden="true">↗</span></a></p>
<div class="reveal">
<label for="group">Group name</label>
<div class="identifier"><input id="group" type="text" name="group" value="${form.group ?? ''}" placeholder="admins" autocomplete="off" autocapitalize="none" spellcheck="false"><span class="suffix">@${provider.domain}</span></div>
</div>
</div></div>
</div>
<div class="card-foot">
<p class="terms">By connecting an app, you agree to our <a href="${TERMS_URL}" target="_blank" rel="noopener">Terms of Service</a> and <a href="${PRIVACY_URL}" target="_blank" rel="noopener">Privacy Policy</a>.</p>
<button type="submit">Connect app</button>
</div>
</form>
${providerSettings(provider, { collapsed: true })}
`;

// The redirect URI, and a second and a third behind an "Add another redirect URI" line each, the way
// a contacts app adds a phone: the line is the summary of a <details> that reveals the next field in
// its place. The summary goes once open (stylesheet), so a typed value cannot be folded away, and the
// third field's line sits inside the second's, so the lines come one at a time. A field comes back
// open when the form returns with a value or the problem in it, and the problem's field is marked.
// The field names are the endpoint's (endpoints/domain.js).
function redirectUriFields({ redirectUris = [], invalid = null }) {
  const field = (i, name) => html`<input id="${name}" type="url" name="${name}" value="${redirectUris[i] ?? ''}"${i === 0 ? html` placeholder="e.g., https://grafana.example.com/login/generic_oauth" required` : ''} autocomplete="off" spellcheck="false"${invalid === i ? html` aria-invalid="true"` : ''}>`;
  const open = (i) => (redirectUris[i] || invalid === i ? 'open' : '');
  return html`<label for="redirect_uri">Redirect URI<span class="aka">(sometimes called <em>Callback URL</em> or <em>Redirect URL</em>)</span></label>
${field(0, 'redirect_uri')}
<details class="add" ${open(1) || open(2)}>
<summary><span>Add another redirect URI<span class="hint">For apps whose settings list more than one.</span></span></summary>
<label for="redirect_uri_2">Second redirect URI</label>
${field(1, 'redirect_uri_2')}
<details class="add" ${open(2)}>
<summary><span>Add another redirect URI</span></summary>
<label for="redirect_uri_3">Third redirect URI</label>
${field(2, 'redirect_uri_3')}
</details>
</details>`;
}

function banner(domain, status) {
  if (status?.configured === false) {
    return html`<p class="warn"><strong>${domain} isn't set up for triauth yet</strong><br/> You can connect apps now, but nobody can sign in until the domain has a <code>triauth</code> DNS record.<br/><a href="https://www.triauth.org/identity/get-started">Set up this domain for triauth</a></p>`;
  }
  if (status && status.configured === null) {
    return html`<p class="note"><strong>DNS couldn't be read just now.</strong> The domain's status is unknown. Reload the page in a moment.</p>`;
  }
  return '';
}
