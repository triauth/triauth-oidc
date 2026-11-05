/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// The credentials just created, shown once, in the same cards as the domain's page.
//
//   provider      the domain's provider, with its URLs
//   credentials   {clientId, clientSecret (null for an app without one), hosts, redirectUris, group
//                 (null when everyone at the domain may sign in)}
//   app           {name, how, docs, setup} for an app recognised by its redirect URI, or null

import { html } from '../lib/html.js';
import { breakAfterDots, providerSettings, valueRows } from './partials.js';

export default ({ provider, credentials, app }) => html`
<div class="page-head">
<h1>OpenID Connect settings for ${listOf(credentials.hosts.map(breakAfterDots))}</h1>
</div>
<p class="lead">Once you copy these settings to ${listOf(credentials.hosts)} ${credentials.group
    ? html`members of the <strong>${credentials.group}@${provider.domain}</strong> group`
    : html`everyone with an identifier under the <strong>@${provider.domain}</strong> domain`} will be able to sign in there with triauth.</p>
${credentials.clientSecret
    ? ''
    : html`<p class="note"><strong>This app has no client secret.</strong><br/> It must use PKCE for triauth sign-in to work. Most command-line and mobile apps already do. If yours has a setting for it, look for "PKCE", "Use PKCE" or "Code challenge method" and choose S256.</p>`}
<section class="card">
<div class="card-head">
<h2>App credentials</h2>
<p>Paste these into your app's OpenID Connect settings. Click a value to select it.</p>
</div>
${valueRows([
    ['Client ID', credentials.clientId],
    ['Client secret', credentials.clientSecret ?? html`<span class="muted">None</span>`],
    [credentials.redirectUris.length > 1 ? 'Redirect URIs' : 'Redirect URI', html`${credentials.redirectUris.map((uri) => html`<code class="value">${uri}</code>`)}`],
  ])}

</section>
${providerSettings(provider)}
${app ? html`<section class="card">
<div class="card-head">
<h2>Using ${app.name}?</h2>
<p>${app.how} <a href="${app.docs}">${app.name} docs</a></p>
</div>
<div class="card-body">
<pre>${app.setup}</pre>
</div>
</section>` : ''}
<p><a href="${provider.page}">Connect another app</a></p>`;

/** Items in a sentence: "a", "a and b", "a, b and c". */
function listOf(items) {
  return html`${items.map((item, i) => [i === 0 ? '' : i === items.length - 1 ? ' and ' : ', ', item])}`;
}
