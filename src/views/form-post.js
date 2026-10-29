/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// The page that hands a result to an app that asked for response_mode=form_post. Its one-line script
// submits the form at once; without scripts, the user presses the button.
//
// This is one of the two views that use `raw`: the script is a constant, and the page's
// Content-Security-Policy allows exactly it, by the hash below (pages.js puts the hash into the
// header; the unit tests recompute it).
//
//   action   the app's redirect URI, checked before it got here
//   fields   the result, name -> value: code or error, state, iss
//   host     the app's host, for the title and the button

import { html, raw } from '../lib/html.js';
import { breakAfterDots, hiddenInputs } from './partials.js';

export const FORM_POST_SCRIPT = 'document.forms[0].submit()';
export const FORM_POST_SCRIPT_HASH = 'sha256-ePniVEkSivX/c7XWBGafqh8tSpiRrKiqYeqbG7N1TOE=';

export default ({ action, fields, host }) => html`
<h1>Returning to ${breakAfterDots(host)}</h1>
<form method="post" action="${action}">
  ${hiddenInputs(fields)}
  <noscript><button type="submit">Continue to ${host}</button></noscript>
</form>
<script>${raw(FORM_POST_SCRIPT)}</script>`;
