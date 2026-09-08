// test_whitelist.js - Проверка классификации, привязки белого списка к домену
// и памяти вердикта на время сессии.
// Функции извлекаются из background.js, поэтому тест гоняет тот же код, что
// работает в расширении. Сеть не требуется.

const fs = require('fs');
const path = require('path');
const tls = require('tls');
const assert = require('assert');

const src = fs.readFileSync(path.join(__dirname, 'background.js'), 'utf8');

const FUNCS = ['readTLV', 'children', 'decodeOID', 'parseName', 'parseCertificate', 'computeSha256',
  'formatName', 'findExtensionNodes', 'hasExtension', 'isWhitelisted', 'checkMatch',
  'sameOrigin', 'originKey', 'saveOriginStatus', 'saveTabStatus', 'loadTabStatus',
  'analyzeSecurityInfo'];

let code = src.match(/^const SCT_EXTENSION_OID = [^\n]*;$/m)[0] + '\n';
for (const fn of FUNCS) {
  const m = src.match(new RegExp(String.raw`^(?:async )?function ${fn}\([\s\S]*?\n\}$`, 'm'));
  assert.ok(m, 'В background.js не найдена функция ' + fn);
  code += m[0] + '\n';
}
code += 'let userWhitelist = [];\nconst trustedRootsMap = {};\n';
// Подменяем хранилище браузера обычным объектом: логика памяти сессии
// проверяется без Chrome.
code += 'const tabStatusMap = new Map();\n';
code += 'const __session = {};\n';
code += 'const chrome = { storage: { session: {\n';
code += '  get: async keys => { const o = {}; for (const k of keys) if (k in __session) o[k] = __session[k]; return o; },\n';
code += '  set: async obj => { Object.assign(__session, obj); }\n';
code += '} } };\n';
code += 'module.exports = { analyzeSecurityInfo, setWl: w => { userWhitelist = w; },\n';
code += '  saveTabStatus, saveOriginStatus, loadTabStatus, tabStatusMap, session: __session };\n';

const tmp = path.join(__dirname, '.wl_extracted.tmp.js');
fs.writeFileSync(tmp, code);
const M = require(tmp);

// Самоподписанный корень играет роль локального сертификата: подписей CT нет,
// издатель совпадает с субъектом. Для такого сайта Chrome отдаёт state 'broken'.
const pem = tls.rootCertificates[0];
const der = new Uint8Array(Buffer.from(pem.replace(/-----[^\n]+-----/g, '').replace(/\s+/g, ''), 'base64'));

const FP = 'AA:BB:CC';
const brokenSi = { state: 'broken', certificates: [{ rawDER: der, fingerprint: { sha256: FP } }] };
const MY_SITE = 'https://myserver.local/page';
const OTHER_SITE = 'https://evil.example.com/page';

(async () => {
  try {
    console.log('=== TEST: недействительный сертификат ===');
    M.setWl([]);
    const plain = await M.analyzeSecurityInfo(brokenSi, MY_SITE);

    assert.strictEqual(plain.level, 'danger', 'Недействительный сертификат должен давать danger');
    assert.notStrictEqual(plain.issuerName, 'Недействительный сертификат',
      'Издатель должен разбираться из сертификата, а не подставляться заглушкой');
    assert.ok(plain.issuerName.length > 3, 'Имя издателя пустое');
    assert.strictEqual(plain.fingerprint, FP,
      'Отпечаток обязан попадать в статус — без него нечего добавлять в белый список');
    console.log('✔ danger, издатель разобран: "' + plain.issuerName + '"');

    console.log('=== TEST: доверие привязано к домену ===');
    M.setWl([{ host: 'myserver.local', fingerprint: FP, issuer: plain.issuerName }]);

    const mine = await M.analyzeSecurityInfo(brokenSi, MY_SITE);
    assert.strictEqual(mine.level, 'trusted', 'На разрешённом домене должен стать доверенным');
    assert.strictEqual(mine.whitelisted, true, 'Должна стоять пометка ручного разрешения');
    console.log('✔ на своём домене — trusted');

    const other = await M.analyzeSecurityInfo(brokenSi, OTHER_SITE);
    assert.strictEqual(other.level, 'danger',
      'Тот же сертификат на другом домене доверенным быть не должен');
    console.log('✔ на чужом домене доверие не действует');

    const swapped = { state: 'broken', certificates: [{ rawDER: der, fingerprint: { sha256: 'FF:EE:DD' } }] };
    const changed = await M.analyzeSecurityInfo(swapped, MY_SITE);
    assert.strictEqual(changed.level, 'danger',
      'Подмена сертификата на разрешённом домене должна снова давать danger');
    console.log('✔ подмена сертификата на своём домене ловится');

    console.log('=== TEST: память вердикта на время сессии ===');

    const OWN = 'https://example.org/page';
    const OTHER = 'https://other.example/page';
    const verdict = { level: 'trusted', url: OWN, issuerName: 'Test CA', fingerprint: '11:22' };

    await M.saveTabStatus(7, verdict);
    await M.saveOriginStatus(OWN, verdict);

    const fresh = await M.loadTabStatus(7, OWN);
    assert.ok(fresh, 'Вердикт вкладки должен находиться');
    assert.strictEqual(fresh.level, 'trusted');
    assert.ok(!fresh.fromSessionMemory, 'Свежий вердикт не должен помечаться памятью');
    console.log('✔ вердикт вкладки возвращается как свежий');

    // Вкладка ушла на другой сайт — вердикт прошлого сайта применяться не должен
    const foreign = await M.loadTabStatus(7, OTHER);
    assert.strictEqual(foreign, null, 'Вердикт не должен переезжать на чужое происхождение');
    console.log('✔ на чужом происхождении вердикт не применяется');

    // Запись по вкладке потеряна (выгруженная вкладка, перезапуск воркера),
    // но происхождение уже проверялось в этой сессии
    M.tabStatusMap.clear();
    delete M.session['tab_7'];

    const remembered = await M.loadTabStatus(7, OWN);
    assert.ok(remembered, 'Вердикт должен восстанавливаться из памяти происхождения');
    assert.strictEqual(remembered.level, 'trusted');
    assert.strictEqual(remembered.fromSessionMemory, true,
      'Восстановленный вердикт обязан быть помечен как память сессии');
    console.log('✔ вердикт восстановлен из памяти и честно помечен');

    const nothing = await M.loadTabStatus(7, OTHER);
    assert.strictEqual(nothing, null, 'Для незнакомого происхождения памяти быть не должно');
    console.log('✔ для незнакомого происхождения памяти нет');

    console.log('\n=== ALL WHITELIST TESTS PASSED! ===');
  } finally {
    try { fs.unlinkSync(tmp); } catch (e) { /* уже удалён */ }
  }
})().catch(e => {
  console.error('\nТЕСТ УПАЛ: ' + e.message);
  process.exit(1);
});
