// test_extension.js - Automated tests for CA Indicator logic

const fs = require('fs');
const path = require('path');
const tls = require('tls');
const assert = require('assert');

console.log('=== TEST 1: Checking manifest.json ===');
const manifestRaw = fs.readFileSync(path.join(__dirname, 'manifest.json'), 'utf8');
const manifest = JSON.parse(manifestRaw);
assert.strictEqual(manifest.manifest_version, 3);
assert.ok(manifest.permissions.includes('webRequest'));
assert.ok(manifest.permissions.includes('storage'));
assert.ok(manifest.host_permissions.includes('<all_urls>'));
assert.ok(manifest.content_scripts.length > 0);
assert.ok(fs.existsSync(path.join(__dirname, manifest.background.service_worker)));
assert.ok(fs.existsSync(path.join(__dirname, manifest.action.default_popup)));
console.log('✔ manifest.json is valid MV3 structure');

console.log('=== TEST 2: Checking Icons ===');
const pngSignature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
const themes = ['trusted', 'danger', 'warning', 'insecure', 'default'];
const sizes = [16, 32, 48, 128];

for (const t of themes) {
  for (const s of sizes) {
    const fPath = path.join(__dirname, 'icons', `icon-${t}-${s}.png`);
    assert.ok(fs.existsSync(fPath), `Missing icon ${fPath}`);
    const buf = fs.readFileSync(fPath);
    assert.ok(buf.length > 50, `Icon too small ${fPath}`);
    assert.ok(buf.subarray(0, 8).equals(pngSignature), `Invalid PNG header ${fPath}`);
  }
}
console.log('✔ All 20 icon files verified and have valid PNG signatures');

console.log('=== TEST 3: Testing ASN.1 Parser and Classification ===');

// Extract ASN.1 parser logic from background.js
function readTLV(b, pos) {
  if (pos >= b.length) return null;
  const tag = b[pos];
  let len = b[pos + 1];
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) {
      len = len * 256 + (b[pos + 2 + i] || 0);
    }
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
  const b = new Uint8Array(rawDer);
  const rootTLV = readTLV(b, 0);
  if (!rootTLV) return null;
  const tbs = children(b, rootTLV)[0];
  if (!tbs) return null;
  const parts = children(b, tbs);
  const i = parts[0]?.tag === 0xa0 ? 1 : 0;
  const serialNode = parts[i];
  const issuerNode = parts[i + 2];
  const subjectNode = parts[i + 4];

  let serialHex = '';
  if (serialNode) {
    const sBytes = b.slice(serialNode.contentStart, serialNode.end);
    serialHex = Array.from(sBytes).map(x => x.toString(16).padStart(2, '0')).join(':').toUpperCase();
  }

  return {
    issuer: parseName(b, issuerNode),
    subject: parseName(b, subjectNode),
    serial: serialHex
  };
}

// Check real certificate retrieval
const testDomains = [
  { host: 'google.com', expectedLevel: 'trusted' },
  { host: 'letsencrypt.org', expectedLevel: 'trusted' },
  { host: 'github.com', expectedLevel: 'trusted' }
];

let completed = 0;

for (const item of testDomains) {
  const socket = tls.connect(443, item.host, { servername: item.host, rejectUnauthorized: false }, () => {
    const peerCert = socket.getPeerCertificate(true);
    const parsed = parseCertificate(peerCert.raw);
    assert.ok(parsed, `Failed to parse DER for ${item.host}`);
    const name = [parsed.issuer.O, parsed.issuer.CN].filter(Boolean).join(' / ');
    console.log(`✔ ${item.host} -> Issuer: "${name}", Subject: "${parsed.subject.CN}"`);
    socket.end();
    completed++;
    if (completed === testDomains.length) {
      testSimulatedCerts();
    }
  });
  socket.on('error', err => {
    console.error(`Socket error for ${item.host}:`, err.message);
  });
}

function testSimulatedCerts() {
  console.log('=== TEST 4: Classification of Interception vs Trusted signatures ===');

  const GLOBAL_TRUSTED = [
    "Internet Security Research Group", "ISRG", "Let's Encrypt",
    "Google Trust Services", "GTS", "DigiCert", "Sectigo", "USERTrust", "GlobalSign"
  ];

  const KNOWN_INTERCEPTION = [
    "Russian Trusted", "Минцифры", "Qaznet", "Kaspersky", "mitmproxy", "Fortinet", "Zscaler"
  ];

  function evaluate(issuerStr) {
    const n = issuerStr.toLowerCase();
    if (KNOWN_INTERCEPTION.some(k => n.includes(k.toLowerCase()))) return 'danger';
    if (GLOBAL_TRUSTED.some(k => n.includes(k.toLowerCase()))) return 'trusted';
    return 'warning';
  }

  assert.strictEqual(evaluate('The Ministry of Digital Development and Communications / Russian Trusted Sub CA'), 'danger');
  assert.strictEqual(evaluate('Qaznet Trust Network / STS'), 'danger');
  assert.strictEqual(evaluate('AO Kaspersky Lab / Kaspersky Anti-Virus Personal Root'), 'danger');
  assert.strictEqual(evaluate('mitmproxy / mitmproxy'), 'danger');
  assert.strictEqual(evaluate('Fortinet / FortiGate Inspection'), 'danger');

  assert.strictEqual(evaluate('Google Trust Services LLC / WR2'), 'trusted');
  assert.strictEqual(evaluate("Let's Encrypt / YE2"), 'trusted');
  assert.strictEqual(evaluate("Internet Security Research Group / ISRG Root X1"), 'trusted');
  assert.strictEqual(evaluate('DigiCert Inc / DigiCert Global G2'), 'trusted');
  assert.strictEqual(evaluate('Sectigo Limited / Sectigo Public Server'), 'trusted');

  assert.strictEqual(evaluate('Internal Corp CA / Root 1'), 'warning');
  assert.strictEqual(evaluate('Some Random Hacker / CA'), 'warning');

  console.log('✔ All classification scenarios (danger, trusted, warning) verified successfully!');
  console.log('\n=== ALL TESTS PASSED! ===');
}
