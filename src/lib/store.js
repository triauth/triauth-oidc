/*!
 * Copyright (c) 2026 The Triauth Authors (https://www.triauth.org/)
 * SPDX-License-Identifier: Elastic-2.0
 */

// The Store: the bridge's only storage, a Durable Object with one instance per domain.
//
// A Durable Object is a small single-threaded server with its own storage. One instance handles one
// request at a time, so "read, delete, return" in `take` cannot race with another `take` of the same
// record: whoever comes second finds nothing. That is what makes sign-in records and codes
// single-use. The storage has no expiry of its own, so every record carries its expiry, `take`
// refuses expired ones, and an alarm purges whatever was never taken.
//
// The Store holds only sealed blobs under hashed names (see sealed.js). It knows nothing about
// OIDC or triauth, and a copy of its storage reveals nothing.

import { DurableObject } from 'cloudflare:workers';
import CONFIG from '../../config.js';

export class Store extends DurableObject {

  /**
   * Stores a blob under a name.
   *
   * @param name {string} - The record's name (a hash, see sealed.js).
   * @param blob {string} - The sealed record.
   * @param ttlSeconds {number} - How long the record may be taken.
   */
  async put(name, blob, ttlSeconds) {
    await this.ctx.storage.put(name, { blob, exp: Date.now() + ttlSeconds * 1000 });
    if (await this.ctx.storage.getAlarm() === null) {
      await this.ctx.storage.setAlarm(Date.now() + CONFIG.purgeInterval * 1000);
    }
  }

  /**
   * Reads a blob and deletes it, in one step.
   *
   * @param name {string} - The record's name.
   * @returns {Promise<string|null>} The blob, or null when there is none or it has expired.
   */
  async take(name) {
    const record = await this.ctx.storage.get(name);
    if (!record) {
      return null;
    }
    await this.ctx.storage.delete(name);
    return typeof record.exp === 'number' && Date.now() <= record.exp ? record.blob : null;
  }

  /**
   * Purges expired records, and re-arms itself while records remain.
   */
  async alarm() {
    const now = Date.now();
    let remaining = 0;
    for (const [name, record] of await this.ctx.storage.list()) {
      if (!record || typeof record.exp !== 'number' || now > record.exp) {
        await this.ctx.storage.delete(name);
      } else {
        remaining++;
      }
    }
    if (remaining > 0) {
      await this.ctx.storage.setAlarm(now + CONFIG.purgeInterval * 1000);
    }
  }
}
