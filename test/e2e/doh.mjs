// A fake DNS-over-HTTPS server (dns-json dialect) for the end-to-end tests, after triauth-cf's.
//
// It serves a zone in the shape of the triauth-js JSON fixtures' "dnsEntries":
// { name: { TXT: [string | {value, ttl, dnssec}] } | null | { _error } }. TXT data is answered in
// presentation form (double-quoted character strings), like Cloudflare's endpoint. Each instance keeps
// its own copy of the zone, so a change on one instance (POST /admin/set) makes the two disagree.

import http from 'node:http';

export async function startDoh(initialZone) {
  const zone = structuredClone(initialZone);

  function answer(name, type) {
    const entry = zone[name];
    if (entry && entry._error) {
      return { status: 500, body: { error: entry._error } };
    }
    if (!entry) {
      return { status: 200, body: { Status: 3, AD: true, Question: [{ name, type: 16 }] } };
    }
    const records = (entry[type] || []).map((rec) => typeof rec === 'string' ? { value: rec, ttl: 1800, dnssec: true } : rec);
    return {
      status: 200,
      body: {
        Status: 0,
        AD: records.length > 0 && records.every((rec) => rec.dnssec !== false),
        Question: [{ name, type: 16 }],
        Answer: records.map((rec) => ({ name, type: 16, TTL: rec.ttl ?? 1800, data: `"${rec.value}"` })),
      },
    };
  }

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    if (url.pathname === '/dns-query' && req.method === 'GET') {
      const { status, body } = answer(url.searchParams.get('name'), url.searchParams.get('type') || 'TXT');
      res.writeHead(status, { 'Content-Type': 'application/dns-json' });
      res.end(JSON.stringify(body));
    } else if (url.pathname === '/admin/set' && req.method === 'POST') {
      let raw = '';
      req.on('data', (chunk) => raw += chunk);
      req.on('end', () => {
        const { domain, records } = JSON.parse(raw);
        if (records === null) { delete zone[domain]; } else { zone[domain] = records; }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
      });
    } else {
      res.writeHead(404);
      res.end();
    }
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { port: server.address().port, close: () => new Promise((resolve) => server.close(resolve)) };
}
