// The provider (src/lib/provider.js): domain paths, the allowlist, and the URLs.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { splitDomainPath, isIdentifierDomain, domainAllowed, providerFor } from '../../src/lib/provider.js';

test('paths split into a lowercase domain and the rest', () => {
  assert.deepEqual(splitDomainPath('/example.com'), { domain: 'example.com', rest: null });
  assert.deepEqual(splitDomainPath('/example.com/'), { domain: 'example.com', rest: '' });
  assert.deepEqual(splitDomainPath('/example.com/authorize'), { domain: 'example.com', rest: 'authorize' });
  assert.deepEqual(splitDomainPath('/example.com/apps/app.example.com:8443/callback'), { domain: 'example.com', rest: 'apps/app.example.com:8443/callback' });
  for (const bad of ['/', '//', '/Example.com/', '/example/', '/example.com./', '/-example.com/', '/xn--80ak6aa92e.com/', '/1.2.3.4/', '/example.com:443/', '/exa mple.com/']) {
    assert.equal(splitDomainPath(bad), null, bad);
  }
});

test('favicon.ico and robots.txt look like domains, so the router must serve them first', () => {
  assert.equal(isIdentifierDomain('favicon.ico'), true);
  assert.equal(isIdentifierDomain('robots.txt'), true);
});

test('the DOMAINS allowlist', () => {
  assert.equal(domainAllowed({}, 'any.com'), true);
  assert.equal(domainAllowed({ DOMAINS: '' }, 'any.com'), true);
  assert.equal(domainAllowed({ DOMAINS: ' a.com   b.com ' }, 'b.com'), true);
  assert.equal(domainAllowed({ DOMAINS: 'a.com' }, 'b.com'), false);
});

test('the provider URLs hang off the issuer', () => {
  const p = providerFor('https://oidc.triauth.org', 'example.com');
  assert.equal(p.issuer, 'https://oidc.triauth.org/example.com');
  assert.equal(p.host, 'oidc.triauth.org');
  assert.equal(p.discovery, 'https://oidc.triauth.org/example.com/.well-known/openid-configuration');
  assert.equal(p.jwks, 'https://oidc.triauth.org/example.com/jwks');
  assert.equal(p.authorize, 'https://oidc.triauth.org/example.com/authorize');
  assert.equal(p.token, 'https://oidc.triauth.org/example.com/token');
  assert.equal(p.userinfo, 'https://oidc.triauth.org/example.com/userinfo');
  assert.equal(p.appBase('grafana.example.com'), 'https://oidc.triauth.org/example.com/apps/grafana.example.com/');
  assert.equal(p.callback('grafana.example.com', 'abc'), 'https://oidc.triauth.org/example.com/apps/grafana.example.com/callback?f=abc');
  assert.ok(Object.isFrozen(p));
});
