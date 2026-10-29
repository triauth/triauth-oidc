/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// HTTP helpers shared by the endpoints: reading forms and cookies, writing responses with the right
// headers, CORS for the endpoints that apps call from code, and the rate check for the endpoints
// that resolve DNS or verify signatures.

import { Helpers } from 'triauth';

const MAX_FORM_BYTES = 64 * 1024;

/**
 * Parses a Cookie header.
 *
 * @param header {string|null} - The Cookie header, if any.
 * @returns {Object<string, string>} Cookie name -> value, verbatim.
 */
export function parseCookies(header) {
  const cookies = {};
  for (const part of String(header || '').split(';')) {
    const eq = part.indexOf('=');
    const name = eq > 0 ? part.slice(0, eq).trim() : '';
    if (name !== '') {
      cookies[name] = part.slice(eq + 1).trim();
    }
  }
  return cookies;
}

/**
 * Reads an application/x-www-form-urlencoded request body of at most 64 KB. The size is checked
 * before and while reading, so an oversized body is never buffered.
 *
 * @param request {Request} - The request.
 * @returns {Promise<URLSearchParams|null>} The fields, or null when the body is not a small form.
 */
export async function readForm(request) {
  const type = (request.headers.get('Content-Type') || '').split(';')[0].trim().toLowerCase();
  if (type !== 'application/x-www-form-urlencoded' || Number(request.headers.get('Content-Length') || 0) > MAX_FORM_BYTES) {
    return null;
  }
  const body = await readUpTo(request.body, MAX_FORM_BYTES);
  return body === null ? null : new URLSearchParams(new TextDecoder().decode(body));
}

async function readUpTo(stream, max) {
  if (!stream) {
    return new Uint8Array(0);
  }
  const reader = stream.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    size += value.byteLength;
    if (size > max) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

/**
 * The same-origin guard for the bridge's own forms. A browser sends `Origin` with every POST; a
 * value from another site is a cross-site request. An absent header passes: non-browser clients have
 * no cookies to abuse.
 *
 * @param request {Request} - The request.
 * @param origin {string} - The bridge's origin.
 * @returns {boolean}
 */
export function sameOrigin(request, origin) {
  const header = request.headers.get('Origin');
  return !header || header === origin;
}

/**
 * The per-address rate check, through one of the rate limiting bindings of wrangler.jsonc. Without
 * the binding, as in some local setups, every request passes.
 *
 * @param limiter {object|undefined} - A binding, e.g. env.RATE_LIMIT_LOGIN.
 * @param request {Request} - The request.
 * @returns {Promise<boolean>} True when the request is within the limit.
 */
export async function withinRateLimit(limiter, request) {
  if (!limiter) {
    return true;
  }
  const { success } = await limiter.limit({ key: rateKey(request) });
  return success;
}

/**
 * What a limit counts by: the client's IPv4 address, or the /64 prefix of its IPv6 address, since one
 * subscriber usually holds a whole /64 and could otherwise pick a fresh address for every request.
 *
 * @param request {Request} - The request.
 * @returns {string}
 */
export function rateKey(request) {
  const ip = request.headers.get('CF-Connecting-IP') || 'local';
  if (!ip.includes(':')) {
    return ip;
  }
  const [head, tail = ''] = ip.split('::');
  const first = head ? head.split(':') : [];
  const last = tail ? tail.split(':') : [];
  const groups = [...first, ...Array(Math.max(0, 8 - first.length - last.length)).fill('0'), ...last];
  return groups.slice(0, 4).map((group) => group.toLowerCase().padStart(4, '0')).join(':') + '::/64';
}

/**
 * A random base64url id.
 *
 * @param bytes {number} - Entropy in bytes.
 * @returns {string}
 */
export function randomId(bytes) {
  return Helpers.arrayBufferToBase64Url(crypto.getRandomValues(new Uint8Array(bytes)));
}

/**
 * A Set-Cookie value. Every cookie of the bridge is `__Host-` prefixed (one host, whole site, https),
 * HttpOnly (scripts never see it; the pages have no scripts anyway), and Secure.
 *
 * @param name {string} - The name, which must start with `__Host-`.
 * @param value {string} - The value, or '' to clear.
 * @param maxAge {number} - Seconds; 0 clears the cookie.
 * @param sameSite {'None'|'Lax'} - None for the cookie the authenticator's cross-site POST must bring back.
 * @returns {string}
 */
export function cookie(name, value, maxAge, sameSite) {
  return `${name}=${value}; Max-Age=${maxAge}; Path=/; Secure; HttpOnly; SameSite=${sameSite}`;
}

/**
 * A JSON response that caches nowhere and that browsers never take for anything but JSON, for
 * tokens and claims.
 *
 * @param data {*} - The body.
 * @param [status=200] {number} - The status.
 * @param [headers] {object} - Extra headers.
 * @returns {Response}
 */
export function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'Pragma': 'no-cache',
      'X-Content-Type-Options': 'nosniff',
      ...headers,
    },
  });
}

/**
 * A 302 redirect.
 *
 * @param location {string} - The target.
 * @param [cookies] {Array<string>} - Set-Cookie values.
 * @returns {Response}
 */
export function redirect(location, cookies = []) {
  const headers = new Headers({ 'Location': location, 'Cache-Control': 'no-store' });
  for (const value of cookies) {
    headers.append('Set-Cookie', value);
  }
  return new Response(null, { status: 302, headers });
}

/**
 * Adds the CORS headers that let a browser-based app call discovery, /jwks, /token, and /userinfo.
 * These endpoints use no cookies, so any origin may read them.
 *
 * @param response {Response} - The response to decorate.
 * @returns {Response}
 */
export function withCors(response) {
  const headers = new Headers(response.headers);
  headers.set('Access-Control-Allow-Origin', '*');
  headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  headers.set('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  headers.set('Access-Control-Max-Age', '86400');
  return new Response(response.body, { status: response.status, headers });
}

/**
 * A 405 that names the allowed methods.
 *
 * @param allow {Array<string>} - The methods.
 * @returns {Response}
 */
export function methodNotAllowed(allow) {
  return new Response('Method Not Allowed', { status: 405, headers: { 'Allow': allow.join(', ') } });
}
