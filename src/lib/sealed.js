/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// Sealed, single-use records.
//
// During a sign-in the bridge must remember two things for a short while: the triauth challenge,
// between the redirect to the authenticator and its answer (about three minutes), and the
// authorization code, between the redirect back to the app and the app's /token call (one minute).
// Both live in the Store (store.js), and both are sealed:
//
//   - a fresh 32-byte secret is minted for each record and handed out exactly once: as the browser
//     cookie of the sign-in, or as the authorization code itself;
//   - the record is encrypted with AES-256-GCM under that secret and stored under its kind and the
//     secret's SHA-256, so a secret of one kind cannot even find a record of the other;
//   - the record's kind and domain are authenticated data, so a record cannot pass for another kind
//     or at another domain.
//
// The bridge keeps neither the secret nor its hash, so a copy of the storage reveals nothing, and a
// record can be read only by whoever holds the cookie or the code. `take` deletes the record as it
// reads it, which gives the single use that triauth requires for challenges and OAuth for codes.

import { Helpers } from 'triauth';

const SECRET_BYTES = 32;
export const SECRET_LENGTH = 43;   // base64url of 32 bytes

/**
 * A fresh record secret.
 *
 * @returns {string} 43 base64url characters.
 */
export function newSecret() {
  return Helpers.arrayBufferToBase64Url(crypto.getRandomValues(new Uint8Array(SECRET_BYTES)));
}

/**
 * Seals a record.
 *
 * @param secret {string} - The record's secret, from newSecret.
 * @param binding {{kind: string, domain: string}} - What the record is and whose it is; authenticated, not encrypted.
 * @param data {object} - The record, JSON-shaped.
 * @returns {Promise<{name: string, blob: string}>} The storage name (the secret's hash) and the ciphertext.
 */
export async function seal(secret, binding, data) {
  const bytes = secretBytes(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: bindingBytes(binding) },
    await aesKey(bytes, 'encrypt'),
    new TextEncoder().encode(JSON.stringify(data)),
  );
  return {
    name: `${binding.kind}:${await nameOf(bytes)}`,
    blob: Helpers.arrayBufferToBase64Url(iv) + '.' + Helpers.arrayBufferToBase64Url(ciphertext),
  };
}

/**
 * Opens a sealed record.
 *
 * @param secret {string} - The record's secret.
 * @param binding {{kind: string, domain: string}} - Must equal the binding it was sealed with.
 * @param blob {string} - The ciphertext from seal.
 * @returns {Promise<object|null>} The record, or null when the secret, the binding, or the blob is wrong.
 */
export async function open(secret, binding, blob) {
  try {
    const [iv, ciphertext, rest] = String(blob).split('.');
    if (rest !== undefined || !iv || !ciphertext) {
      return null;
    }
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: Helpers.base64UrlToUint8(iv), additionalData: bindingBytes(binding) },
      await aesKey(secretBytes(secret), 'decrypt'),
      Helpers.base64UrlToUint8(ciphertext),
    );
    return JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    return null;
  }
}

/**
 * The storage name of a record: its kind, then the SHA-256 of its secret, so the name reveals
 * nothing about the key.
 *
 * @param kind {string} - 'signin' or 'code'.
 * @param secret {string} - The record's secret.
 * @returns {Promise<string|null>} Null when the secret is not 43 canonical base64url characters.
 */
export async function nameFor(kind, secret) {
  try {
    return `${kind}:${await nameOf(secretBytes(secret))}`;
  } catch {
    return null;
  }
}

/**
 * The records of one domain, in that domain's Store.
 *
 * @param env {object} - The Worker environment (the STORE binding).
 * @param domain {string} - The provider's domain.
 * @returns {{put: function(string, object, number): Promise<string>, take: function(string, string): Promise<object|null>}}
 */
export function recordsOf(env, domain) {
  const store = env.STORE.get(env.STORE.idFromName(domain));

  return {
    /**
     * Seals and stores a record; returns the secret that reads it back.
     *
     * @param kind {string} - 'signin' or 'code'.
     * @param data {object} - The record.
     * @param ttlSeconds {number} - How long the record may be taken.
     */
    async put(kind, data, ttlSeconds) {
      const secret = newSecret();
      const { name, blob } = await seal(secret, { kind, domain }, data);
      await store.put(name, blob, ttlSeconds);
      return secret;
    },

    /**
     * Takes a record: reads, deletes, and opens it. A second take of the same record finds nothing.
     *
     * @param kind {string} - The kind it must have been stored as.
     * @param secret {*} - The secret from put.
     * @returns {Promise<object|null>} The record, or null when it is missing, expired, or not opened by this secret and kind.
     */
    async take(kind, secret) {
      const name = typeof secret === 'string' && secret.length === SECRET_LENGTH ? await nameFor(kind, secret) : null;
      if (name === null) {
        return null;
      }
      const blob = await store.take(name);
      return blob === null ? null : open(secret, { kind, domain }, blob);
    },
  };
}

function secretBytes(secret) {
  const bytes = Helpers.base64UrlToUint8(String(secret));
  if (bytes.length !== SECRET_BYTES) {
    throw new TypeError('A record secret has 32 bytes');
  }
  return bytes;
}

function bindingBytes({ kind, domain }) {
  return new TextEncoder().encode(`${kind}\0${domain}`);
}

async function nameOf(bytes) {
  return Helpers.arrayBufferToBase64Url(await crypto.subtle.digest('SHA-256', bytes));
}

function aesKey(bytes, usage) {
  return crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, [usage]);
}
