// The Worker under test: the real src/ and config.js, with the DoH endpoints pointed at the fake
// servers. The bridge builds its resolver on first use, so this adjustment lands in time.

import { env } from 'cloudflare:workers';
import config from '../../config.js';

Object.assign(config, {
  doh: [`http://127.0.0.1:${env.TEST_DOH_A_PORT}/dns-query`, `http://127.0.0.1:${env.TEST_DOH_B_PORT}/dns-query`],
  dohMaxFailures: 0,
});

export { Store } from '../../src/lib/store.js';
export { default } from '../../src/index.js';
