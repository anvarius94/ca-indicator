// test_aia_chain.js - Проверка достройки цепочки по AIA и криптографической
// проверки подписей. Функции извлекаются прямо из background.js, поэтому тест
// гоняет ровно тот код, который работает в расширении.
//
// Требует сети: подключается к живым сайтам и скачивает сертификаты издателей.

const fs = require('fs');
const path = require('path');
const tls = require('tls');
const assert = require('assert');

const src = fs.readFileSync(path.join(__dirname, 'background.js'), 'utf8');

const STR_CONSTS = ['AIA_OID', 'CA_ISSUERS_OID', 'PKCS7_SIGNED_DATA_OID', 'SCT_EXTENSION_OID',
  'AIA_MAX_DEPTH', 'AIA_TIMEOUT_MS'];
const OBJ_CONSTS = ['RSA_SIG_ALGS', 'EC_SIG_ALGS', 'EC_CURVES'];
const FUNCS = [
  'readTLV', 'children', 'decodeOID', 'parseName', 'parseCertificate', 'computeSha256',
  'formatName', 'findExtensionNodes', 'hasExtension', 'bytesToB64', 'b64ToBytes',
  'looksLikeCertificate', 'extractCertsFromPkcs7', 'getExtensionValueNode', 'getCaIssuerUrls',
  'getSignatureInfo', 'tbsParts', 'getSpkiNode', 'getIssuerDer', 'getSubjectDer', 'getEcCurve',
  'derEcdsaToRaw', 'verifyChildAgainstSpki', 'verifyCertSignature', 'findIssuingRoot',
  'fetchIssuerCerts', 'verifyChainViaAia'
];

let code = '';
for (const c of STR_CONSTS) {
  const m = src.match(new RegExp(String.raw`^const ${c} = [^\n]*;$`, 'm'));
  assert.ok(m, 'В background.js не найдена константа ' + c);
  code += m[0] + '\n';
}
for (const c of OBJ_CONSTS) {
  const m = src.match(new RegExp(String.raw`^const ${c} = \{[\s\S]*?\n\};$`, 'm'));
  assert.ok(m, 'В background.js не найден объект ' + c);
  code += m[0] + '\n';
}
for (const fn of FUNCS) {
  const m = src.match(new RegExp(String.raw`^(?:async )?function ${fn}\([\s\S]*?\n\}$`, 'm'));
  assert.ok(m, 'В background.js не найдена функция ' + fn);
  code += m[0] + '\n';
}
code += 'const aiaCache = new Map();\n';
code += 'const trustedRootsMap = require(' + JSON.stringify(path.join(__dirname, 'trusted_roots.json')) + ').roots;\n';
code += 'module.exports = { verifyChainViaAia, getCaIssuerUrls, verifyCertSignature, fetchIssuerCerts };\n';

const tmp = path.join(__dirname, '.aia_extracted.tmp.js');
fs.writeFileSync(tmp, code);
const M = require(tmp);

function leafOf(host) {
  return new Promise((resolve, reject) => {
    const s = tls.connect(443, host, { servername: host, rejectUnauthorized: false }, () => {
      const der = s.getPeerCertificate(true).raw;
      s.end();
      resolve(new Uint8Array(der));
    });
    s.on('error', reject);
  });
}

(async () => {
  try {
    console.log('=== Достройка цепочки по AIA до корня из базы ===');

    // Покрывают оба семейства алгоритмов и оба способа доставки издателя:
    // голый DER, PKCS#7 (Sectigo) и корень без AIA у промежуточного (GlobalSign).
    const hosts = ['google.com', 'letsencrypt.org', 'github.com', 'support.kaspersky.ru', 'ya.ru'];

    for (const host of hosts) {
      const leaf = await leafOf(host);
      const r = await M.verifyChainViaAia(leaf);

      assert.strictEqual(r.outcome, 'root-found', host + ': цепочка не достроена до корня (' + r.outcome + ')');
      assert.strictEqual(r.trusted, true, host + ': цепочка не признана доверенной');
      assert.strictEqual(r.anyBroken, false, host + ': в цепочке есть несходящаяся подпись');

      const root = r.chain[r.chain.length - 1];
      assert.ok(root.knownRootName, host + ': последний элемент цепочки не корень из базы');

      const verified = r.chain.filter(c => c.signatureVerified === true).length;
      assert.ok(verified >= 1, host + ': ни одна подпись не проверена');

      console.log('✔ ' + host.padEnd(22) + r.chain.length + ' сертификата, подписей проверено: ' +
        verified + ', корень: ' + root.knownRootName);
    }

    console.log('=== Негативный контроль: подделка должна отвергаться ===');

    const leaf = await leafOf('google.com');
    const urls = M.getCaIssuerUrls(leaf);
    assert.ok(urls.length, 'У листа google.com не найден AIA');

    const issuers = await M.fetchIssuerCerts(urls[0]);
    assert.ok(issuers.length, 'Не удалось скачать сертификат издателя');

    const good = await M.verifyCertSignature(leaf, issuers[0]);
    assert.strictEqual(good, true, 'Подлинная подпись не прошла проверку');
    console.log('✔ подлинный сертификат: подпись сходится');

    // Портим один байт внутри TBSCertificate — подпись обязана перестать сходиться
    const tampered = new Uint8Array(leaf);
    tampered[60] = tampered[60] ^ 0xff;
    const bad = await M.verifyCertSignature(tampered, issuers[0]);
    assert.strictEqual(bad, false, 'Подделанный сертификат прошёл проверку подписи!');
    console.log('✔ изменённый байт в TBS: подпись отвергнута');

    console.log('\n=== ALL AIA TESTS PASSED! ===');
  } finally {
    try { fs.unlinkSync(tmp); } catch (e) { /* уже удалён */ }
  }
  // fetch в Node держит keep-alive соединения ещё минуты, поэтому выходим сами
  process.exit(0);
})().catch(e => {
  console.error('\nТЕСТ УПАЛ: ' + e.message);
  process.exit(1);
});
