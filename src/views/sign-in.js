/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// The sign-in page: which app asks, and the username field with the domain fixed, in a narrow card in
// the middle, as on most sign-in pages. The app's authorization request rides along as hidden fields,
// so that /login can check it again.
//
//   domain        the identities' domain, fixed
//   host          the app's host, from its redirect URI
//   redirectUri   the full redirect URI, in the tooltip of the app's host
//   loginUrl      the form's target
//   appAddress    the app's address on the bridge, which the authenticator will show
//   username      the prefilled username, or ''
//   error         a sentence about a failed attempt, or null
//   fields        the request's fields to carry along, name -> value
//
// Focus starts in the username field when it is empty or holds a value to fix after an error. When the
// field is prefilled (a remembered username or a login_hint), focus starts on the Continue button
// instead: Enter continues, and Shift+Tab lands in the field with the whole value selected, so typing
// replaces it. The autofocus attribute would leave the caret at the start of the value.
//
// The line under the card is how the person signing in agrees to the Terms: "By continuing" names the
// Continue button right above it (the Terms count "clicking a button that refers to them"). The
// Privacy Policy is left to the footer, because it is a notice that nobody agrees to.

import { html } from '../lib/html.js';
import { breakAfterDots, hiddenInputs, TERMS_URL } from './partials.js';

export default ({ domain, host, redirectUri, loginUrl, appAddress, username, error, fields }) => {
  const focusInput = !username || error;
  return html`
<div class="sign-in">
<h1>Sign in to <span class="mark" title="${redirectUri}">${breakAfterDots(host)}</span></h1>
<form class="card" method="post" action="${loginUrl}">
${hiddenInputs(fields)}
<div class="card-body">
${error ? html`<p class="err">${error}</p>` : ''}
<label for="username">Your identifier</label>
<div class="identifier">
  <input id="username" type="text" name="username" value="${username}" placeholder="e.g., john" autocomplete="username" autocapitalize="none" spellcheck="false" inputmode="email" required ${focusInput ? 'autofocus' : ''}>
  <span class="suffix">@${domain}</span>
</div>
</div>
<div class="card-foot">
<button type="submit" ${focusInput ? '' : 'autofocus'}>Continue</button>
</div>
</form>
<p class="terms">By continuing, you agree to the triauth <a href="${TERMS_URL}" target="_blank" rel="noopener">Terms of Service</a>.</p>
</div>`;
};
