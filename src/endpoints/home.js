/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// GET /  (and the static /favicon.svg, /favicon.ico and /robots.txt)
//
// Arrives:  a visitor, or the home page form with ?domain=.
// Checks:   that the typed domain (or identifier) is a domain name this bridge may serve.
// Stores:   nothing.
// Next:     the domain's page, or the home page with a message.

import { isIdentifierDomain, domainAllowed } from '../lib/provider.js';
import { homePage } from '../lib/pages.js';
import { redirect } from '../lib/http.js';

export async function page({ url, env }) {
  const typed = url.searchParams.get('domain');
  if (typed === null) {
    return homePage();
  }
  // Forgive an identifier, a URL, or capitals: take the domain out of what was typed.
  const domain = typed.trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/\/.*$/, '').replace(/^.*@/, '');
  if (isIdentifierDomain(domain) && domainAllowed(env, domain)) {
    return redirect(`/${domain}/`);
  }
  return homePage({ problem: `“${typed}” isn't a domain this bridge can serve. Try one like example.com.` });
}

// The mark as on www.triauth.org: its favicon.svg, copied as it is, with its own colour for dark
// mode. Pages link it as /favicon.svg; /favicon.ico answers with the same file for clients that ask
// for that name without reading the page.
const FAVICON = `<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg width="180" height="180" viewBox="0 0 180 180" version="1.1" xmlns="http://www.w3.org/2000/svg">
  <style>
    path { fill: #494949; }
    @media (prefers-color-scheme: dark) { path { fill: #b6b6b6; } }
  </style>
  <path d="m 48.046615,144.18979 v -13.98448 h 13.110433 13.110434 v 13.98448 13.98446 H 61.157048 48.046615 Z M 105.73251,89.999999 V 76.015537 h 13.11044 13.11044 V 89.999999 103.98446 H 118.84295 105.73251 Z M 48.046615,35.810208 V 21.825746 H 61.157048 74.267482 V 35.810208 49.79467 H 61.157048 48.046615 Z"/>
</svg>`;

export function favicon() {
  return new Response(FAVICON, { headers: { 'Content-Type': 'image/svg+xml', 'Cache-Control': 'public, max-age=86400' } });
}

export function robots() {
  return new Response('User-agent: *\nDisallow: /\n', { headers: { 'Content-Type': 'text/plain', 'Cache-Control': 'public, max-age=86400' } });
}
