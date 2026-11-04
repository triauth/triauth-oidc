/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// Signing keys.
//
// The bridge signs ID tokens and access tokens with RSA (RS256), the one algorithm every OpenID
// Connect app accepts. Apps verify the signatures with the public keys at the provider's JWKS URL.
// Each key has a `kid` (key ID), named in every token header, so an app knows which published key
// to use. The `kid` is the key's RFC 7638 thumbprint, so it never needs to be chosen or stored.
//
// Keys live in two Worker secrets, SIGNING_KEY_A and SIGNING_KEY_B, each an RSA private key as a JWK
// made by bin/keygen.mjs. The variable SIGNING_KEY_ACTIVE names the slot that signs; every filled
// slot is published, so a key can be published a day before it starts signing, and stays accepted
// after it stops (README, Operations, has the rotation steps). If the active slot is empty, the
// other filled slot signs, so a wrong pointer does not stop the bridge.
//
// Refresh tokens (refresh.js) are sealed under a secret derived from a slot's private key with HKDF,
// so that the bridge needs no secret beyond its signing keys. Each slot carries its `sealingSecret`.
// A token names the slot it was sealed under, so it outlives a rotation while the slot stays
// published, and dies with the slot when a leaked key is deleted.

import { Helpers } from 'triauth';

const ALGORITHM = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
const SLOTS = ['A', 'B'];
const SEALING_INFO = 'triauth-oidc/v1/refresh';

// Imported CryptoKeys per JWK text, for the life of the isolate: importing an RSA key costs CPU.
const imported = new Map();
const warned = new Set();

/**
 * Loads the key slots.
 *
 * @param env {object} - The Worker environment.
 * @returns {Promise<{signing: (object|null), published: Array<object>}>} `signing` is the slot that signs
 *          (null when no slot is filled); `published` lists every filled slot. A slot is
 *          `{slot, kid, privateKey, publicKey, publicJwk, sealingSecret}`.
 */
export async function loadKeys(env) {
  const slots = [];
  for (const slot of SLOTS) {
    const key = await loadSlot(slot, env[`SIGNING_KEY_${slot}`]);
    if (key) {
      slots.push(key);
    }
  }
  const active = String(env.SIGNING_KEY_ACTIVE || 'A').toUpperCase();
  const signing = slots.find((key) => key.slot === active) || slots[0] || null;
  if (signing && signing.slot !== active && !warned.has(active)) {
    warned.add(active);
    console.error(`[triauth-oidc] SIGNING_KEY_ACTIVE names slot ${active}, which is empty; signing with slot ${signing.slot}`);
  }
  return { signing, published: slots };
}

/**
 * The public keys of every filled slot, as a JWK Set for the /jwks endpoint.
 *
 * @param env {object} - The Worker environment.
 * @returns {Promise<{keys: Array<object>}>}
 */
export async function publishedJwks(env) {
  const { published } = await loadKeys(env);
  return { keys: published.map((key) => key.publicJwk) };
}

/**
 * The RFC 7638 thumbprint of an RSA public key: the SHA-256 of its required members in lexicographic order.
 *
 * @param jwk {{e: string, n: string}} - The public key.
 * @returns {Promise<string>} base64url.
 */
export async function thumbprint(jwk) {
  const canonical = JSON.stringify({ e: jwk.e, kty: 'RSA', n: jwk.n });
  return Helpers.arrayBufferToBase64Url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical)));
}

async function loadSlot(slot, text) {
  if (typeof text !== 'string' || text.trim() === '') {
    return null;
  }
  if (!imported.has(text)) {
    imported.set(text, importSlot(slot, text));
  }
  return imported.get(text);
}

async function importSlot(slot, text) {
  try {
    const jwk = JSON.parse(text);
    if (jwk.kty !== 'RSA' || typeof jwk.n !== 'string' || typeof jwk.e !== 'string' || typeof jwk.d !== 'string') {
      throw new Error('not an RSA private JWK');
    }
    const publicJwk = { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', use: 'sig', kid: await thumbprint(jwk) };
    return {
      slot,
      kid: publicJwk.kid,
      privateKey: await crypto.subtle.importKey('jwk', jwk, ALGORITHM, false, ['sign']),
      publicKey: await crypto.subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e }, ALGORITHM, false, ['verify']),
      publicJwk,
      sealingSecret: await sealingSecretOf(jwk),
    };
  } catch {
    // The value is never quoted, not even through the error's message: whatever was pasted into the
    // slot must not end up in the log.
    console.error(`[triauth-oidc] SIGNING_KEY_${slot} is not an RSA private key in JWK form; the slot is treated as empty`);
    return null;
  }
}

/**
 * The secret that seals a slot's refresh tokens: 32 bytes from HKDF-SHA256 over the private exponent,
 * as the 43 base64url characters that sealed.js takes as a record secret. The same key gives the same
 * secret in every isolate, and the RSA key itself is never used for anything but signing.
 *
 * @param jwk {{d: string}} - The slot's private key as a JWK; only the private exponent is read.
 * @returns {Promise<string>} 43 base64url characters.
 */
async function sealingSecretOf(jwk) {
  const key = await crypto.subtle.importKey('raw', Helpers.base64UrlToUint8(jwk.d), 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode(SEALING_INFO) },
    key,
    256,
  );
  return Helpers.arrayBufferToBase64Url(bits);
}
