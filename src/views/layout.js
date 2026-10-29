/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// The frame of every page, as on the other plain triauth pages: the document head with the inline
// stylesheet, one line at the top with the mark and the bridge's name, the page's body in a readable
// column, and the footer. `wide` widens the column for the dashboard pages (home, a domain, its credentials).
// `build` is the version and the source this build was made from (src/build-info.js), for the footer's link.
//
// This is one of the two views that use `raw`: the stylesheet is a constant of this repository.

import { html, raw } from '../lib/html.js';
import { TERMS_URL, PRIVACY_URL, REPO_URL } from './partials.js';
import style from './style.js';

export default ({ title, body, wide = false, build = {} }) => html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>${raw(style)}</style>
</head>
<body${wide ? html` class="wide"` : ''}>
<header><a href="/"><span class="mark">⠕</span>triauth <span class="name">OpenID Connect bridge</span></a></header>
<main>
${body}
</main>
<footer>&copy; 2026 <a href="https://www.triauth.org/">triauth.org</a> | <a href="${build.sourceUrl || REPO_URL}">triauth-oidc${build.version ? ` v${build.version}` : ''}</a> | <a href="${TERMS_URL}">Terms</a> | <a href="${PRIVACY_URL}">Privacy</a></footer>
</body>
</html>
`;
