/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// Pieces that several views share.

import { html } from '../lib/html.js';

/**
 * The operator's Terms of Service and Privacy Policy, linked from the footer of every page and from
 * the notice next to the button that creates credentials. triauth.org's Terms cover the services it
 * runs under its own subdomains, not a bridge someone else runs: another operator links their own.
 */
export const TERMS_URL = 'https://www.triauth.org/legal/terms';
export const PRIVACY_URL = 'https://www.triauth.org/legal/privacy';

// The showcase of apps on www.triauth.org
export const EVERYWHERE_URL = 'https://www.triauth.org/everywhere/';

/**
 * Where the bridge's source lives, linked from the footer. A build links to the exact commit it was
 * made from instead, when that is known (src/build-info.js, written by bin/build-info.mjs).
 */
export const REPO_URL = 'https://github.com/triauth/triauth-oidc';

/**
 * A domain or host name that may wrap after any of its dots, so that a long one breaks between its
 * labels rather than inside one, as in a heading on a phone. The breaks add no characters: the name
 * copies whole.
 *
 * @param name {string} - The domain or host name.
 * @returns {Html}
 */
export function breakAfterDots(name) {
  return html`${name.split('.').map((label, i) => (i === 0 ? label : html`.<wbr>${label}`))}`;
}

/**
 * One hidden input per field. Fields without a value are left out.
 *
 * @param fields {Object<string, (string|undefined)>} - Field names and values.
 * @returns {Array<Html>}
 */
export function hiddenInputs(fields) {
  return Object.entries(fields).filter(([, value]) => value !== undefined)
    .map(([name, value]) => html`<input type="hidden" name="${name}" value="${value}">`);
}

/**
 * Label and value rows, as in a settings card. A string value is something to copy: it is set in
 * monospace and selects as a whole with one click. An Html value goes in as it is.
 *
 * @param rows {Array<[string, (string|Html)]>} - Labels and values.
 * @returns {Html}
 */
export function valueRows(rows) {
  return html`<dl class="rows">${rows.map(([label, value]) => html`
<div><dt>${label}</dt><dd>${typeof value === 'string' ? html`<code class="value">${value}</code>` : value}</dd></div>`)}
</dl>`;
}

/**
 * The provider's settings, for an admin to copy into an app. `collapsed` folds them into one quiet
 * line below the form, for the domain's page, where they are rarely needed: the credentials page
 * shows them again. A click opens them without a script (a <details> element). The credentials page
 * shows them open, as a card.
 *
 * @param provider {object} - The domain's provider, with its URLs.
 * @param [options] {{collapsed?: boolean}}
 * @returns {Html}
 */
export function providerSettings(provider, { collapsed = false } = {}) {
  const rows = valueRows([
    ['Issuer', provider.issuer],
    ['Discovery', provider.discovery],
    ['Auth URL', provider.authorize],
    ['Token URL', provider.token],
    ['Userinfo URL', provider.userinfo],
    ['JWKS URL', provider.jwks],
    ['Scopes', 'openid email profile groups'],
  ]);
  if (collapsed) {
    return html`<details class="more">
<summary>View provider settings</summary>
${rows}
</details>`;
  }
  return html`<section class="card">
<div class="card-head">
<h2>Provider settings</h2>
</div>
${rows}
</section>`;
}
