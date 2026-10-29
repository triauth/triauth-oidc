// The app (the "relying party"), played by openid-client, an independent OpenID Connect
// implementation. It talks to the Worker through SELF.fetch, so discovery, the token exchange, the
// ID token checks (signature, issuer, audience, nonce, expiry) and userinfo are all its own doing.

import * as oidc from 'openid-client';
import { SELF } from 'cloudflare:test';

export { oidc };

const fetchViaWorker = (url, options) => SELF.fetch(url, options);

/**
 * Discovers a provider and configures the client.
 *
 * @param issuer {string} - The issuer URL.
 * @param clientId {string} - The client ID.
 * @param options {{secret?: string, method?: 'basic'|'post'|'none'}} - How the client authenticates at /token.
 */
export async function discover(issuer, clientId, { secret = undefined, method = 'basic' } = {}) {
  const auth = method === 'basic' ? oidc.ClientSecretBasic(secret) : method === 'post' ? oidc.ClientSecretPost(secret) : oidc.None();
  const config = await oidc.discovery(new URL(issuer), clientId, undefined, auth, { [oidc.customFetch]: fetchViaWorker });
  config[oidc.customFetch] = fetchViaWorker;
  return config;
}

/** Fresh PKCE, state and nonce for one sign-in, and the authorization URL for them. */
export async function startAuthorization(config, redirectUri, extra = {}) {
  const verifier = oidc.randomPKCECodeVerifier();
  const checks = { pkceCodeVerifier: verifier, expectedState: oidc.randomState(), expectedNonce: oidc.randomNonce() };
  const url = oidc.buildAuthorizationUrl(config, {
    redirect_uri: redirectUri,
    scope: 'openid email profile groups',
    state: checks.expectedState,
    nonce: checks.expectedNonce,
    code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
    code_challenge_method: 'S256',
    ...extra,
  });
  return { url, checks };
}
