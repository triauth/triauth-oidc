/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// JSON Web Tokens, signed with RS256.
//
// A JWT is three base64url parts joined by dots: a header such as {"alg":"RS256","typ":"JWT","kid":…},
// a payload (the claims, as JSON), and an RSA signature over `header.payload`. ID tokens and access
// tokens are JWTs. This file signs and verifies them, and nothing else: what goes into a payload is
// decided by the endpoint that issues the token.

import { Helpers } from 'triauth';

const ALGORITHM = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
const CLOCK_SKEW = 60;   // seconds of tolerance for `iat` in the future

/**
 * Signs a token.
 *
 * @param header {object} - The header; `alg` is set to RS256 here.
 * @param payload {object} - The claims.
 * @param privateKey {CryptoKey} - The signing key, from keys.js.
 * @returns {Promise<string>} The compact JWT.
 */
export async function signJwt(header, payload, privateKey) {
  const signingInput = encode({ ...header, alg: 'RS256' }) + '.' + encode(payload);
  const signature = await crypto.subtle.sign(ALGORITHM, privateKey, new TextEncoder().encode(signingInput));
  return signingInput + '.' + Helpers.arrayBufferToBase64Url(signature);
}

/**
 * Takes a token apart without checking anything.
 *
 * @param token {*} - The compact JWT.
 * @returns {{header: object, payload: object, signingInput: string, signature: Uint8Array}|null} Null when it is not three decodable parts.
 */
export function decodeJwt(token) {
  try {
    const parts = String(token).split('.');
    if (parts.length !== 3) {
      return null;
    }
    const header = JSON.parse(Helpers.base64UrlToString(parts[0]));
    const payload = JSON.parse(Helpers.base64UrlToString(parts[1]));
    if (!isObject(header) || !isObject(payload)) {
      return null;
    }
    return { header, payload, signingInput: parts[0] + '.' + parts[1], signature: Helpers.base64UrlToUint8(parts[2]) };
  } catch {
    return null;
  }
}

/**
 * Verifies a token this bridge issued: the signature under one of the published keys, and the claims
 * that every verifier must check.
 *
 * @param token {*} - The compact JWT.
 * @param expected {{keys: Array<{kid: string, publicKey: CryptoKey}>, issuer: string, audience: string, typ: string}} -
 *        The published keys, and the `iss`, `aud`, and header `typ` the token must carry.
 * @returns {Promise<object|null>} The payload when every check passes, null otherwise.
 */
export async function verifyJwt(token, expected) {
  const decoded = decodeJwt(token);
  if (!decoded) {
    return null;
  }
  const { header, payload, signingInput, signature } = decoded;

  const key = header.alg === 'RS256' && typeof header.kid === 'string'
    ? expected.keys.find((k) => k.kid === header.kid)
    : undefined;
  if (!key || header.typ !== expected.typ) {
    return null;
  }

  const valid = await crypto.subtle.verify(ALGORITHM, key.publicKey, signature, new TextEncoder().encode(signingInput));
  if (!valid) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (
    payload.iss !== expected.issuer ||
    !audiences.includes(expected.audience) ||
    typeof payload.exp !== 'number' || payload.exp <= now ||
    typeof payload.iat !== 'number' || payload.iat > now + CLOCK_SKEW
  ) {
    return null;
  }

  return payload;
}

function encode(object) {
  return Helpers.stringToBase64Url(JSON.stringify(object));
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
