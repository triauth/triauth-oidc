/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// The page behind an app's address on the bridge, which the authenticator's home-screen tile opens.
// The bridge never redirects there by itself (an automatic redirect would make it an open
// redirector, RFC 9700 §4.11): the person sees where the button goes before pressing it.
//
//   domain   the identities' domain
//   host     the app's host
//   url      the root URL of the app's host, checked by the endpoint (appRootUrl)

import { html } from '../lib/html.js';
import { breakAfterDots } from './partials.js';

export default ({ domain, host, url }) => html`
<div style="text-align:center;">
<h1>Open ${breakAfterDots(host)}?</h1>
<p class="muted">Sign in to <strong>${host}</strong> with your <strong>@${domain}</strong> identifier</p>
<a class="button" href="${url}" autofocus>Open ${host}</a>
</div>`;
