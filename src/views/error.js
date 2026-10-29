/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// An error page, with an optional way back to the app that the user starts: a link, or a form that
// posts the fields for an app that takes its result as a form post. The bridge never redirects by
// itself.
//
//   title      the heading
//   text       one or two sentences
//   returnTo   {url, host} for a link, {action, fields, host} for a form, or null

import { html } from '../lib/html.js';
import { hiddenInputs } from './partials.js';

export default ({ title, text, returnTo }) => html`
<h1>${title}</h1>
<p class="lead">${text}</p>
${wayBack(returnTo)}`;

function wayBack(returnTo) {
  if (!returnTo) {
    return '';
  }
  if (returnTo.action) {
    return html`<form method="post" action="${returnTo.action}">${hiddenInputs(returnTo.fields)}<button type="submit">Return to ${returnTo.host}</button></form>`;
  }
  return html`<a class="button" href="${returnTo.url}">Return to ${returnTo.host}</a>`;
}
