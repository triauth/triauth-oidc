// The scripted authenticator: reads the challenge out of the redirect that /login answers, signs it
// with fixture keys through the triauth-js signer stub (copied into ./triauth-js/, see its README),
// and seals the response as the real authenticator does (HPKE to the challenge's `ek`). The bridge
// cannot tell the difference.

import * as Triauth from 'triauth';
import Signer from './triauth-js/signer.js';
import identities from './triauth-js/identities.json';
import { BASE, DOMAIN } from './client.js';

globalThis.Triauth = Triauth;   // the signer stub reaches the library through a global

export const john = identities.john;
export const JOHN_DESKTOP = john.devices[0].keys;
export const JOHN_LAPTOP = john.devices[1].keys;

/** The challenge the authenticator receives: the `challenge` parameter in the redirect's fragment. */
export function challengeFrom(location) {
  return new URLSearchParams((location || '').split('#?')[1] || '').get('challenge');
}

/** The callback URL the challenge names (with its `?f=` flow id). */
export function callbackUrlOf(challenge) {
  return Triauth.Challenge.fromString(challenge).data.cburl;
}

/** The manifest the challenge carries for the authenticator's home-screen tile. */
export function manifestOf(challenge) {
  return Triauth.Challenge.fromString(challenge).data.ext?.manifest;
}

/** The base URL that the authenticator shows and signs as `via`: the app's address on the bridge. */
export function via(host, domain = DOMAIN) {
  return `${BASE}/${domain}/apps/${host}/`;
}

/**
 * Approves a challenge: signs it for `identifier` (as `actor`, when delegated) with the device keys,
 * and seals the envelope to the challenge's encryption key.
 */
export async function approve(challenge, { identifier, keys, host, domain = DOMAIN, actor = '' }) {
  const envelope = await Triauth.Signature.generate(Signer.signUsingDeviceKeys(keys), 'auth', identifier, actor, via(host, domain), challenge);
  const ek = Triauth.Challenge.fromString(challenge).data.ek;
  return (await Triauth.ResponseCipher.seal(ek, envelope)).sealedResponse;
}
