/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// triauth-oidc: an OpenID Connect provider for triauth identities, as one Cloudflare Worker.
//
// This file is the map. Every URL is one row below, and every row is one file in endpoints/, which
// starts with what arrives, what is checked, what is stored, and where the browser goes next. The
// concepts the endpoints share (the provider, app credentials, the authorization request, keys, JWTs,
// sealed records, the triauth sign-in, the pages) are one file each in lib/. The Store class is the
// Durable Object that keeps the sealed records; wrangler.jsonc binds it as STORE.
//
//   GET  /                                          endpoints/home.js
//   GET  /{domain}/                                 endpoints/domain.js      the admin's page
//   POST /{domain}/credentials                      endpoints/domain.js      client ID and secret for an app
//   GET  /{domain}/.well-known/openid-configuration endpoints/discovery.js   what this provider supports
//   GET  /{domain}/jwks                             endpoints/discovery.js   the public signing keys
//   GET  /{domain}/authorize                        endpoints/authorize.js   the app's request -> the sign-in page
//   POST /{domain}/login                            endpoints/login.js       triauth stage 1 -> the authenticator
//   POST /{domain}/apps/{host}/callback             endpoints/callback.js    triauth stage 3 -> back to the app with a code
//   GET  /{domain}/apps/{host}/                     endpoints/callback.js    the app's address, for the authenticator's tile
//   POST /{domain}/token                            endpoints/token.js       code -> ID token and access token
//   GET  /{domain}/userinfo                         endpoints/userinfo.js    claims for an access token
//
// Discovery also answers under the name .well-known/oauth-authorization-server, and at the RFC 8414
// addresses /.well-known/openid-configuration/{domain} and /.well-known/oauth-authorization-server/{domain},
// which put the well-known segment before the issuer's path. Some libraries look there for an issuer
// that has a path. HEAD is answered like GET, without the body.

import * as home from './endpoints/home.js';
import * as domain from './endpoints/domain.js';
import * as discovery from './endpoints/discovery.js';
import * as authorize from './endpoints/authorize.js';
import * as login from './endpoints/login.js';
import * as callback from './endpoints/callback.js';
import * as token from './endpoints/token.js';
import * as userinfo from './endpoints/userinfo.js';
import { splitDomainPath, domainAllowed, providerFor } from './lib/provider.js';
import { errorPage } from './lib/pages.js';
import { redirect, json, withCors, methodNotAllowed } from './lib/http.js';

export { Store } from './lib/store.js';

// The app's host in a path: a lowercase host name or IPv4 address, with an optional port.
const APP_HOST = '([a-z0-9.-]+(?::[0-9]{1,5})?)';

// The routes under /{domain}/. `cors` marks the endpoints that apps call from code, which answer
// preflights and send CORS headers, because they use no cookies.
const ROUTES = [
  { path: '',                                       methods: ['GET'],         handler: domain.page },
  { path: 'credentials',                            methods: ['POST'],        handler: domain.credentials },
  { path: '.well-known/openid-configuration',       methods: ['GET'],         handler: discovery.configuration, cors: true },
  { path: '.well-known/oauth-authorization-server', methods: ['GET'],         handler: discovery.configuration, cors: true },
  { path: 'jwks',                                   methods: ['GET'],         handler: discovery.jwks, cors: true },
  { path: 'authorize',                              methods: ['GET', 'POST'], handler: authorize.handle },
  { path: 'login',                                  methods: ['POST'],        handler: login.handle },
  { path: 'token',                                  methods: ['POST'],        handler: token.handle, cors: true },
  { path: 'userinfo',                               methods: ['GET', 'POST'], handler: userinfo.handle, cors: true },
  { path: new RegExp(`^apps/${APP_HOST}/$`),         methods: ['GET'],  handler: callback.tile, params: ['host'] },
  { path: new RegExp(`^apps/${APP_HOST}/callback$`), methods: ['POST'], handler: callback.handle, params: ['host'] },
];

const INTERNAL_ERROR_TEXT = 'The bridge hit an internal error. Please try again in a moment.';

export default {
  async fetch(request, env) {
    try {
      return finish(request, await route(request, env));
    } catch (err) {
      logFailure(request, err);
      return finish(request, errorPage({ title: 'Something went wrong', text: INTERNAL_ERROR_TEXT, status: 500 }));
    }
  },
};

async function route(request, env) {
  const url = new URL(request.url);
  const method = request.method === 'HEAD' ? 'GET' : request.method;   // HEAD is GET without the body; finish() drops it

  // https only. Cloudflare says how the visitor connected; plain http gets sent to https (and
  // nothing else), so no token, code, or cookie ever travels unencrypted. Local `wrangler dev`
  // sends no CF-Visitor header and is left alone.
  if (/"scheme"\s*:\s*"http"/.test(request.headers.get('CF-Visitor') || '')) {
    if (method !== 'GET') {
      return new Response('Use https.', { status: 400 });
    }
    url.protocol = 'https:';
    return new Response(null, { status: 301, headers: { 'Location': url.toString(), 'Cache-Control': 'no-store' } });
  }

  // The root, and static files whose names look like domain names.
  if (url.pathname === '/') {
    return method === 'GET' ? home.page({ request, env, url }) : methodNotAllowed(['GET']);
  }
  if (url.pathname === '/favicon.svg' || url.pathname === '/favicon.ico') {
    return home.favicon();
  }
  if (url.pathname === '/robots.txt') {
    return home.robots();
  }

  // Everything else is under a domain.
  const split = splitDomainPath(wellKnownAfterDomain(url.pathname));
  if (!split || !domainAllowed(env, split.domain)) {
    return notFound();
  }
  if (split.rest === null) {
    return redirect(`/${split.domain}/`);
  }
  const provider = providerFor(url.origin, split.domain);

  for (const entry of ROUTES) {
    const match = typeof entry.path === 'string'
      ? (split.rest === entry.path ? [] : null)
      : (split.rest.match(entry.path)?.slice(1) ?? null);
    if (match === null) {
      continue;
    }
    if (entry.cors && method === 'OPTIONS') {
      return withCors(new Response(null, { status: 204 }));
    }
    if (!entry.methods.includes(method)) {
      return methodNotAllowed(entry.methods);
    }
    const params = Object.fromEntries((entry.params || []).map((name, i) => [name, match[i]]));
    let response;
    try {
      response = await entry.handler({ request, env, url, provider, params });
    } catch (err) {
      // A handler that fails answers in its route's format: JSON for the endpoints that apps call
      // from code, a page for the ones people see.
      logFailure(request, err);
      response = entry.cors
        ? json({ error: 'server_error', error_description: INTERNAL_ERROR_TEXT }, 500)
        : errorPage({ title: 'Something went wrong', text: INTERNAL_ERROR_TEXT, status: 500 });
    }
    return entry.cors ? withCors(response) : response;
  }

  return notFound();
}

/**
 * RFC 8414 puts the well-known segment before the issuer's path (/.well-known/openid-configuration/{domain});
 * OpenID Connect Discovery puts it after (/{domain}/.well-known/openid-configuration). Both name the
 * same document, so the RFC 8414 spelling becomes the OpenID Connect one before routing.
 *
 * @param pathname {string} - The request path.
 * @returns {string}
 */
function wellKnownAfterDomain(pathname) {
  const match = pathname.match(/^\/\.well-known\/(openid-configuration|oauth-authorization-server)\/([^/]+)$/);
  return match ? `/${match[2]}/.well-known/${match[1]}` : pathname;
}

function notFound() {
  return errorPage({ title: 'Not found', text: 'There is nothing at this address.', status: 404 });
}

function logFailure(request, err) {
  console.error(`[triauth-oidc] ${request.method} ${new URL(request.url).pathname} failed: ${err && err.stack || err}`);
}

/** Tells browsers to use https for this host for a year (HSTS), and drops the body of a HEAD response. */
function finish(request, response) {
  const headers = new Headers(response.headers);
  headers.set('Strict-Transport-Security', 'max-age=31536000');
  return new Response(request.method === 'HEAD' ? null : response.body, { status: response.status, headers });
}
