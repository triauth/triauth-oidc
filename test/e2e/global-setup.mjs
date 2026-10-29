// Runs in Node before the tests: hosts two fake DoH servers with a zone built from the triauth-js
// fixtures (copied into ./triauth-js/, see its README), mints the bridge's signing key for this run,
// and hands ports and key to the tests through provide()/inject().

import { readFileSync } from 'node:fs';
import { startDoh } from './doh.mjs';

const FIXTURES = new URL('./triauth-js/', import.meta.url);

export default async function ({ provide }) {
  const auth = JSON.parse(readFileSync(new URL('auth.json', FIXTURES), 'utf8'));
  const identities = JSON.parse(readFileSync(new URL('identities.json', FIXTURES), 'utf8'));
  const johnDesktop = identities.john.devices[0].keys[0].public;

  const zone = {
    // The demo domain and john, as in the fixtures, plus a groups record.
    'triauthdemo.org': auth.dnsEntries['triauthdemo.org'],
    'john._at.triauthdemo.org': { TXT: [...auth.dnsEntries['john._at.triauthdemo.org'].TXT, 'groups admins,dev'] },
    // An identity without keys of its own that lets john sign on its behalf (a delegation).
    'jane._at.triauthdemo.org': { TXT: ['name Jane Roe', 'include john@triauthdemo.org scope=any'] },
    // A second domain where john's desktop key is also published, for the cross-domain tests.
    'other.example': { TXT: ['triauth auth.other.example mode=public'] },
    'john._at.other.example': { TXT: [`key desktop[1/1]:${johnDesktop}`] },
    // A domain without a triauth record.
    'unconfigured.example': { TXT: [] },
  };

  const pair = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  provide('signingKeyA', JSON.stringify(await crypto.subtle.exportKey('jwk', pair.privateKey)));

  const dohA = await startDoh(zone);
  const dohB = await startDoh(zone);
  provide('dohAPort', dohA.port);
  provide('dohBPort', dohB.port);

  return async () => {
    await dohA.close();
    await dohB.close();
  };
}
