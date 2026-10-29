# triauth-js test files, copied

The end-to-end suite plays the user's authenticator with the signer stub and the fixture identities
of [triauth-js](https://github.com/triauth/triauth-js), and builds its fake DNS zone from the
`dnsEntries` of the `auth` conformance suite. They are copied here so that a checkout of this
repository tests on its own.

| File | In triauth-js |
|---|---|
| `signer.js` | `test/stubs/signer.js` |
| `identities.json` | `test/fixtures/identities.json` |
| `auth.json` | `test/fixtures/json/auth.json` |

Copied unchanged from commit `e4223d21f0405851214c15d4d1c3f83c84e388b6` (the `v1.0.0-beta.4` tag, 2026-10-26).
Apache-2.0, © 2026 The Triauth Authors, as listed in [THIRD-PARTY-NOTICES.txt](../../../THIRD-PARTY-NOTICES.txt);
the rest of this repository is under the Elastic License 2.0.

To refresh from a sibling checkout:

```sh
cp ../triauth-js/test/stubs/signer.js ../triauth-js/test/fixtures/identities.json ../triauth-js/test/fixtures/json/auth.json test/e2e/triauth-js/
```
