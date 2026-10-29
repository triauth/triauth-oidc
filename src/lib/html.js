/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// HTML building blocks, and the headers of every page.
//
// `html` is a template tag that escapes every interpolated value, so a view cannot forget to escape.
// `raw` marks the few fragments that go in as they are: the stylesheet and the one hashed script, both
// constants of this repository, never anything from a request. The escaping covers the five HTML
// metacharacters, which makes a value safe as element text and inside a quoted attribute. It does not
// make a URL safe for href or action: a `javascript:` URL escapes cleanly and still runs, so every URL
// that reaches a page was checked first (credentials.js does that for redirect URIs).
//
// Nothing here touches a Response or any other platform API, so the same code runs in workerd and in
// Node, where the unit tests render every view.

/** A fragment of HTML that is safe to insert as it is. Only `html` and `raw` make one. */
export class Html {
  constructor(text) { this.text = text; }
  toString() { return this.text; }
}

/**
 * Marks text as HTML that needs no escaping. For constants of this repository only, never for a
 * value that a request or a person can set.
 *
 * @param text {string} - The fragment.
 * @returns {Html}
 */
export const raw = (text) => new Html(String(text));

/**
 * A template tag for HTML. Every interpolated value is escaped, except fragments that `html` or `raw`
 * made. Arrays are joined, and null, undefined and false render as nothing, which makes conditional
 * fragments easy: ${condition && html`…`}.
 *
 * @returns {Html}
 */
export function html(strings, ...values) {
  let out = '';
  strings.forEach((part, i) => {
    out += part;
    if (i < values.length) {
      out += render(values[i]);
    }
  });
  return new Html(out);
}

function render(value) {
  if (value instanceof Html) { return value.text; }
  if (Array.isArray(value)) { return value.map(render).join(''); }
  if (value === null || value === undefined || value === false) { return ''; }
  return escape(String(value));
}

/**
 * Escapes the five HTML metacharacters.
 *
 * @param text {*} - Stringified first.
 * @returns {string}
 */
export function escape(text) {
  return String(text).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/**
 * The security headers of every page. No scripts (except the one a page allows by its hash), no
 * framing, no caching; the Referer keeps the origin, because the authenticator checks where the
 * browser came from; and no `form-action`, because Chrome would apply it to the redirect that follows
 * the login POST, which goes to the user's own authenticator.
 *
 * @param [options] {{scriptHash?: string}} - The CSP hash of the one script a page may run.
 * @returns {Object<string, string>}
 */
export function pageHeaders({ scriptHash = null } = {}) {
  const scripts = scriptHash ? `script-src '${scriptHash}'` : "script-src 'none'";
  return {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Security-Policy': `default-src 'none'; ${scripts}; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'`,
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
  };
}
