// A browser for the tests: a cookie jar over the Worker's fetch handler. Redirects are never
// followed, because the interesting part of a sign-in is in them. Each jar has its own client IP, so
// the per-IP rate limit sees one "user" per jar.

import { SELF } from 'cloudflare:test';

export const BASE = 'https://oidc.test';
export const DOMAIN = 'triauthdemo.org';

let jars = 0;

export function makeJar() {
  jars += 1;
  return { cookies: new Map(), ip: `10.${(jars >> 16) & 255}.${(jars >> 8) & 255}.${jars & 255}` };
}

export function cookieHeader(jar) {
  return [...jar.cookies].map(([name, value]) => `${name}=${value}`).join('; ');
}

/**
 * One request, with cookie-jar bookkeeping.
 *
 * @param jar {object} - From makeJar.
 * @param method {string} - HTTP method.
 * @param path {string} - A path under BASE, or an absolute URL.
 * @param [options] {{headers?: object, form?: object}} - `form` is sent url-encoded.
 */
export async function req(jar, method, path, { headers = {}, form = null } = {}) {
  const init = { method, redirect: 'manual', headers: { 'CF-Connecting-IP': jar.ip, ...headers } };
  if (jar.cookies.size) {
    init.headers['Cookie'] = cookieHeader(jar);
  }
  if (form) {
    init.headers['Content-Type'] = 'application/x-www-form-urlencoded';
    init.body = new URLSearchParams(form).toString();
  }
  const res = await SELF.fetch(path.startsWith('http') ? path : BASE + path, init);
  for (const setCookie of res.headers.getSetCookie()) {
    const [pair, ...attrs] = setCookie.split(';');
    const eq = pair.indexOf('=');
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    const gone = attrs.some((a) => a.trim().toLowerCase() === 'max-age=0');
    if (gone || value === '') { jar.cookies.delete(name); } else { jar.cookies.set(name, value); }
  }
  return res;
}

/** The hidden fields of a page, as a browser would submit them. */
export function hiddenFields(html) {
  const fields = {};
  for (const match of html.matchAll(/<input type="hidden" name="([^"]+)" value="([^"]*)">/g)) {
    fields[decodeEntities(match[1])] = decodeEntities(match[2]);
  }
  return fields;
}

export function decodeEntities(text) {
  return text.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
}
