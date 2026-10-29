// End-to-end tests: the real Worker (src/, config.js, wrangler.jsonc) runs inside workerd through
// @cloudflare/vitest-plugin, against two fake DNS-over-HTTPS servers and a scripted authenticator
// that global-setup.mjs hosts in Node. openid-client plays the app. Unit tests are plain `node --test`.
import { defineConfig } from 'vitest/config';
import { cloudflareTest } from '@cloudflare/vitest-plugin';

export default defineConfig({
  plugins: [
    cloudflareTest(({ inject }) => ({
      main: './test/e2e/worker.js',
      wrangler: { configPath: './wrangler.jsonc' },
      miniflare: {
        bindings: {
          SIGNING_KEY_A: inject('signingKeyA'),
          SIGNING_KEY_ACTIVE: 'A',
          DOMAINS: '',
          DEBUG: '',
          TEST_DOH_A_PORT: String(inject('dohAPort')),
          TEST_DOH_B_PORT: String(inject('dohBPort')),
        },
      },
    })),
  ],
  test: {
    include: ['test/e2e/**/*.test.js'],
    globalSetup: ['./test/e2e/global-setup.mjs'],
    testTimeout: 30000,
  },
});
