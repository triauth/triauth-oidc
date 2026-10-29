/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// The pages people see, as responses.
//
// The markup and the wording live in views/, one file per page, each a pure function of plain values.
// This file is the glue between an endpoint and a view: it works out the values the view needs,
// renders the view into the layout, and adds what a Response needs: the security headers (html.js),
// the status, and the cookies. Anything that takes logic (the Grafana block, the hidden fields of a
// request) is computed here, so the views only place values.
//
// Escaping needs no attention in either place: the `html` tag escapes every value, and `raw` appears
// only in the layout (the stylesheet) and in the form_post view (the hashed script).

import { pageHeaders } from './html.js';
import { carriedFields } from './request.js';
import { appSetup, appGuides } from './apps.js';
// The version and the source this build was made from, written by bin/build-info.mjs before every build.
import { version, sourceUrl } from '../build-info.js';
import layout from '../views/layout.js';
import homeView from '../views/home.js';
import domainView from '../views/domain.js';
import credentialsView from '../views/credentials.js';
import signInView from '../views/sign-in.js';
import errorView from '../views/error.js';
import tileView from '../views/tile.js';
import formPostView, { FORM_POST_SCRIPT_HASH } from '../views/form-post.js';

/**
 * Renders a page body into the layout and builds the Response.
 *
 * @param options {{title: string, body: Html, status?: number, cookies?: Array<string>, wide?: boolean, scriptHash?: string}}
 * @returns {Response}
 */
export function page({ title, body, status = 200, cookies = [], wide = false, scriptHash = null }) {
  const headers = new Headers(pageHeaders({ scriptHash }));
  for (const value of cookies) {
    headers.append('Set-Cookie', value);
  }
  return new Response(layout({ title, body, wide, build: { version, sourceUrl } }).toString(), { status, headers });
}

/**
 * The home page: what this is, and a form that opens a domain's page.
 */
export function homePage({ problem = null } = {}) {
  return page({ title: 'triauth OpenID Connect bridge', wide: true, body: homeView({ problem }) });
}

/**
 * A domain's page: whether it is set up for triauth, the settings to copy, and the credentials form.
 *
 * @param options {{provider: object, status?: object, form?: {redirectUri?: string, publicClient?: boolean, limitGroup?: boolean, group?: string, problem?: string}, httpStatus?: number}}
 */
export function domainPage({ provider, status = null, form = {}, httpStatus = 200 }) {
  return page({
    title: `${provider.domain} · triauth OpenID Connect provider`,
    status: httpStatus,
    wide: true,
    body: domainView({ provider, status, form, guides: appGuides() }),
  });
}

/**
 * The credentials just created, shown once, with the setup for the app when its redirect URI tells
 * which app it is (apps.js).
 */
export function credentialsPage({ provider, credentials }) {
  return page({
    title: `Credentials for ${credentials.host} · ${provider.domain}`,
    wide: true,
    body: credentialsView({ provider, credentials, app: appSetup(provider, credentials) }),
  });
}

/**
 * The sign-in page: which app asks, and the username field with the domain fixed. The authorization
 * request rides along as hidden fields.
 *
 * @param options {{provider: object, request: object, host: string, username?: string, error?: string, status?: number, cookies?: Array<string>}}
 */
export function signInPage({ provider, request, host, username = '', error = null, status = 200, cookies = [] }) {
  return page({
    title: `Sign in to ${host} · ${provider.domain}`,
    status,
    cookies,
    body: signInView({
      domain: provider.domain,
      host,
      redirectUri: request.redirect_uri,
      loginUrl: provider.login,
      appAddress: provider.appBase(host),
      username,
      error,
      fields: Object.fromEntries(carriedFields(request)),
    }),
  });
}

/**
 * An error page. With `returnTo`, it offers a way back to the app that the user starts: a link
 * (`url`), or a form that posts `fields` to `action` for an app that takes its result as a form post.
 * The bridge never redirects by itself.
 *
 * @param options {{title: string, text: string, returnTo?: ({url: string, host: string}|{action: string, fields: object, host: string}), status?: number, cookies?: Array<string>}}
 */
export function errorPage({ title, text, returnTo = null, status = 400, cookies = [] }) {
  return page({ title, status, cookies, body: errorView({ title, text, returnTo }) });
}

/**
 * The page behind an app's address on the bridge, which the authenticator's home-screen tile opens.
 *
 * @param options {{provider: object, host: string, url: string}} - `url` is the root URL of the app's host, from appRootUrl.
 * @returns {Response}
 */
export function tilePage({ provider, host, url }) {
  return page({ title: `${host} · sign-in bridge`, body: tileView({ domain: provider.domain, host, url }) });
}

/**
 * The form_post page: hands the result to an app that asked for response_mode=form_post. Its one
 * script is allowed by its hash in the Content-Security-Policy.
 *
 * @param options {{action: string, fields: object, host: string, cookies?: Array<string>}}
 */
export function formPostPage({ action, fields, host, cookies = [] }) {
  return page({
    title: `Returning to ${host}`,
    cookies,
    scriptHash: FORM_POST_SCRIPT_HASH,
    body: formPostView({ action, fields, host }),
  });
}
