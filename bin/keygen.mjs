#!/usr/bin/env node
/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */
// Prints a fresh RSA-2048 private key as a JWK, on one line, for a signing key slot:
//
//   node bin/keygen.mjs | npx wrangler secret put SIGNING_KEY_A
//
// The key goes straight from this process into Cloudflare. The script refuses to print to a terminal,
// so that no copy lands in a scrollback or a clipboard by accident. See README, Operations.

if (process.stdout.isTTY) {
  console.error('Refusing to print a private key to a terminal.');
  console.error('Pipe it into Cloudflare instead:  node bin/keygen.mjs | npx wrangler secret put SIGNING_KEY_A');
  process.exit(1);
}

const keyPair = await crypto.subtle.generateKey(
  { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
  true,
  ['sign', 'verify'],
);

const jwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
delete jwk.key_ops;
delete jwk.ext;
jwk.alg = 'RS256';
jwk.use = 'sig';

process.stdout.write(JSON.stringify(jwk) + '\n');
