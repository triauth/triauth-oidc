#!/usr/bin/env node
/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// Writes src/build-info.js, the module behind the footer of every page: the bridge's version, from
// package.json, and the address of the source this build was made from. Runs before every
// `wrangler dev` and `wrangler deploy` (wrangler.jsonc, `build.command`) and before the tests.
//
// The source address is the repository, or the exact commit when it is known, as on
// triauth-authenticator: SOURCE_REPOSITORY_URL names the repository (default: the triauth-oidc
// repository on GitHub), and SOURCE_COMMIT or WORKERS_CI_COMMIT_SHA (set by Workers Builds) names the
// commit. Without them, the HEAD of a clean checkout counts, because what is deployed is then exactly
// that commit; a checkout with changes links to the repository only.

import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { REPO_URL } from '../src/views/partials.js';

const root = new URL('../', import.meta.url);
const target = new URL('src/build-info.js', root);

const { version } = JSON.parse(readFileSync(new URL('package.json', root), 'utf8'));

const configured = (process.env.SOURCE_REPOSITORY_URL ?? '').trim().replace(/\/+$/, '');
const repository = /^https:\/\/\S+$/.test(configured) ? configured : REPO_URL;

const isSha = (value) => /^[0-9a-f]{40}$/.test(value ?? '');
const commit = [process.env.SOURCE_COMMIT, process.env.WORKERS_CI_COMMIT_SHA].find(isSha) ?? headOfCleanCheckout();
const sourceUrl = commit ? `${repository}/tree/${commit}` : repository;

const text = `/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// Written by bin/build-info.mjs before every build; git-ignored. Do not edit.
export const version = ${JSON.stringify(version)};
export const sourceUrl = ${JSON.stringify(sourceUrl)};
`;

let current = null;
try {
  current = readFileSync(target, 'utf8');
} catch {
  // not written yet
}
if (current !== text) {
  writeFileSync(target, text);
}

/**
 * The HEAD commit when git is available and the checkout has no changes, tracked or untracked;
 * otherwise ''.
 */
function headOfCleanCheckout() {
  const git = (...args) => execFileSync('git', args, {
    cwd: fileURLToPath(root),
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  }).trim();
  try {
    if (git('status', '--porcelain') !== '') return '';
    const head = git('rev-parse', 'HEAD');
    return isSha(head) ? head : '';
  } catch {
    return '';
  }
}
