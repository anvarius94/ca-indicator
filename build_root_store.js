// build_root_store.js - Downloads and parses Chrome Root Store & Mozilla NSS roots into trusted_roots.json
const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const tls = require('tls');

function readTLV(b, pos) {
  if (pos >= b.length) return null;
  const tag = b[pos];
  let len = b[pos + 1];
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + (b[pos + 2 + i] || 0);
    hdr = 2 + n;
  }
  return { tag, contentStart: pos + hdr, end: pos + hdr + len };
}

function children(b, node) {
  const out = [];
  if (!node) return out;
  let p = node.contentStart;
  while (p < node.end) {
    const t = readTLV(b, p);
    if (!t || t.end > node.end) break;
    out.push(t);
    p = t.end;
  }
  return out;
}

function decodeOID(b, n) {
  const s = b.slice(n.contentStart, n.end);
  if (s.length === 0) return '';
  const parts = [Math.floor(s[0] / 40), s[0] % 40];
  let v = 0;
  for (let i = 1; i < s.length; i++) {
    v = v * 128 + (s[i] & 0x7f);
    if (!(s[i] & 0x80)) { parts.push(v); v = 0; }
  }
  return parts.join('.');
}

function parseName(b, nameNode) {
  const res = { CN: '', O: '', OU: '', C: '' };
  if (!nameNode) return res;
  for (const rdn of children(b, nameNode)) {
    for (const atv of children(b, rdn)) {
      const ch = children(b, atv);
      if (ch.length < 2) continue;
      const [oidNode, valNode] = ch;
      const oid = decodeOID(b, oidNode);
      try {
        const val = new TextDecoder('utf-8', { fatal: false }).decode(
          b.slice(valNode.contentStart, valNode.end)
        );
        if (oid === '2.5.4.3') res.CN = val;
        else if (oid === '2.5.4.10') res.O = val;
        else if (oid === '2.5.4.11') res.OU = val;
        else if (oid === '2.5.4.6') res.C = val;
      } catch (e) {}
    }
  }
  return res;
}

function parseCertificate(rawDer) {
  try {
    const b = new Uint8Array(rawDer);
    const rootTLV = readTLV(b, 0);
    if (!rootTLV) return null;
    const tbs = children(b, rootTLV)[0];
    if (!tbs) return null;
    const parts = children(b, tbs);
    const i = parts[0]?.tag === 0xa0 ? 1 : 0;
    const subjectNode = parts[i + 4];
    return { subject: parseName(b, subjectNode) };
  } catch (e) {
    return null;
  }
}

function parsePemCerts(pemStr, source) {
  const matches = pemStr.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
  const list = [];
  for (const m of matches) {
    const b64 = m.replace(/-----[^\n]+-----/g, '').replace(/\s+/g, '');
    const der = Buffer.from(b64, 'base64');
    const sha256 = crypto.createHash('sha256').update(der).digest('hex').toUpperCase();
    const fp = sha256.match(/.{2}/g).join(':');
    const parsed = parseCertificate(der);
    const name = [parsed?.subject?.O, parsed?.subject?.CN].filter(Boolean).join(' / ') || 'Unknown Root';
    list.push({ hash: fp, name, source });
  }
  return list;
}

const googleUrl = 'https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.certs?format=TEXT';

console.log('Downloading official Chrome Root Store from Google...');
https.get(googleUrl, { headers: { 'User-Agent': 'Node' } }, res => {
  let data = '';
  res.on('data', chunk => data += chunk);
  res.on('end', () => {
    let googleCerts = [];
    if (res.statusCode === 200) {
      const raw = Buffer.from(data, 'base64').toString('utf8');
      googleCerts = parsePemCerts(raw, 'Google Chrome Root Store');
      console.log(`Fetched ${googleCerts.length} certificates from Google.`);
    }

    const mozillaCerts = parsePemCerts(tls.rootCertificates.join('\n'), 'Mozilla NSS');
    console.log(`Parsed ${mozillaCerts.length} certificates from Mozilla.`);

    const rootsMap = {};
    for (const c of [...googleCerts, ...mozillaCerts]) {
      rootsMap[c.hash] = {
        name: c.name,
        source: c.source
      };
    }

    const outPath = path.join(__dirname, 'trusted_roots.json');
    fs.writeFileSync(outPath, JSON.stringify({
      version: '1.0',
      updatedAt: new Date().toISOString(),
      count: Object.keys(rootsMap).length,
      roots: rootsMap
    }, null, 2));

    console.log(`Saved ${Object.keys(rootsMap).length} verified root hashes to ${outPath}`);
  });
}).on('error', err => {
  console.error('Error fetching from Google, using built-in Mozilla roots:', err.message);
  const mozillaCerts = parsePemCerts(tls.rootCertificates.join('\n'), 'Mozilla NSS');
  const rootsMap = {};
  for (const c of mozillaCerts) {
    rootsMap[c.hash] = { name: c.name, source: c.source };
  }
  const outPath = path.join(__dirname, 'trusted_roots.json');
  fs.writeFileSync(outPath, JSON.stringify({
    version: '1.0',
    updatedAt: new Date().toISOString(),
    count: Object.keys(rootsMap).length,
    roots: rootsMap
  }, null, 2));
  console.log(`Saved ${Object.keys(rootsMap).length} roots to ${outPath}`);
});
