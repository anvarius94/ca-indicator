// background.js - CA Indicator Service Worker
// 100% Offline, Privacy-Preserving Certificate Trust & MITM Interception Detector

// ===== 1. Списки доверенных и подозрительных центров =====

// Списков имён УЦ здесь больше нет. Они были принципиально ненадёжны: вердикт
// выносился сравнением подстрок в имени издателя, поэтому любой УЦ вне списка
// объявлялся подозрительным, а короткие сигнатуры вроде "WE" совпадали случайно.
// Классификация теперь строится на Certificate Transparency, см. analyzeSecurityInfo.

// In-memory кэш статуса для вкладок
const tabStatusMap = new Map();

// Service worker в MV3 засыпает примерно через 30 секунд простоя, и Map очищается.
// Дублируем статус в storage.session, иначе popup видит пустоту и ошибочно
// показывает «включите флаг» на полностью рабочей конфигурации.
async function saveTabStatus(tabId, data) {
  tabStatusMap.set(tabId, data);
  try {
    await chrome.storage.session.set({ ['tab_' + tabId]: data });
  } catch (e) { /* storage.session недоступен */ }
}

async function loadTabStatus(tabId) {
  if (tabStatusMap.has(tabId)) return tabStatusMap.get(tabId);
  try {
    const key = 'tab_' + tabId;
    const res = await chrome.storage.session.get([key]);
    if (res && res[key]) {
      tabStatusMap.set(tabId, res[key]);
      return res[key];
    }
  } catch (e) { /* ignore */ }
  return null;
}

// Сколько https-ответов увидел «зондовый» слушатель. Если их уже несколько,
// а securityInfo не пришёл ни разу — фича в браузере действительно выключена.
let httpsResponsesSeen = 0;

// Сколько раз securityInfo реально доехал с момента запуска воркера.
let securityInfoDeliveries = 0;

// Пользовательский белый список УЦ
let userWhitelist = [];

// Подтвержден ли флаг Chrome (если securityInfo получен хоть раз)
let flagConfirmed = false;

// База криптографических SHA-256 хэшей официального Chrome Root Store и Mozilla NSS
let trustedRootsMap = {};
let rootStoreUpdatedAt = '2026-09-08';

async function initRootStore() {
  try {
    const res = await chrome.storage.local.get(['userWhitelist', 'flagConfirmed', 'customRoots', 'rootStoreUpdatedAt']);
    if (Array.isArray(res.userWhitelist)) {
      userWhitelist = res.userWhitelist;
    }
    if (res.flagConfirmed) {
      flagConfirmed = true;
    }
    // Встроенная база читается всегда, скачанная накладывается сверху:
    // обновление из сети ДОПОЛНЯЕТ комплектные корни, а не заменяет их.
    const resp = await fetch(chrome.runtime.getURL('trusted_roots.json'));
    const data = await resp.json();
    if (data && data.roots) {
      trustedRootsMap = { ...data.roots };
      if (data.updatedAt) rootStoreUpdatedAt = data.updatedAt;
    }
    if (res.customRoots && Object.keys(res.customRoots).length > 0) {
      trustedRootsMap = { ...trustedRootsMap, ...res.customRoots };
      if (res.rootStoreUpdatedAt) rootStoreUpdatedAt = res.rootStoreUpdatedAt;
    }
  } catch (e) {
    console.error('Error loading trusted roots in worker:', e);
  }
}
initRootStore();

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local') {
    if (changes.userWhitelist) userWhitelist = changes.userWhitelist.newValue || [];
    if (changes.flagConfirmed) flagConfirmed = changes.flagConfirmed.newValue || false;
    if (changes.customRoots) initRootStore();
    if (changes.rootStoreUpdatedAt) rootStoreUpdatedAt = changes.rootStoreUpdatedAt.newValue || '';
  }
});

// ===== 2. Парсер ASN.1 X.509 DER =====

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
    if (!(s[i] & 0x80)) {
      parts.push(v);
      v = 0;
    }
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
      } catch (e) {
        // Ignore decoding error
      }
    }
  }
  return res;
}

// OID 1.3.6.1.4.1.11129.2.4.2 — встроенные Signed Certificate Timestamps.
// Публичный УЦ обязан их проставить, а получить их можно только от CT-логов,
// которые принимают сертификаты исключительно от публично доверенных центров.
// Локально установленный корень (антивирус, DPI, госперехват) их поставить не может.
const SCT_EXTENSION_OID = '1.3.6.1.4.1.11129.2.4.2';

// extensions лежат в TBSCertificate под контекстным тегом [3] (0xA3),
// внутри — SEQUENCE OF Extension, каждый Extension начинается с OID.
function findExtensionNodes(b, tbsNode) {
  for (const c of children(b, tbsNode)) {
    if (c.tag === 0xa3) {
      const seq = children(b, c)[0];
      return seq ? children(b, seq) : [];
    }
  }
  return [];
}

function hasExtension(b, tbsNode, oid) {
  for (const ext of findExtensionNodes(b, tbsNode)) {
    const idNode = children(b, ext)[0];
    if (idNode && decodeOID(b, idNode) === oid) return true;
  }
  return false;
}

function parseCertificate(rawDer) {
  try {
    const b = new Uint8Array(rawDer);
    const rootTLV = readTLV(b, 0);
    if (!rootTLV) return null;
    const tbs = children(b, rootTLV)[0];
    if (!tbs) return null;
    const parts = children(b, tbs);
    const i = parts[0]?.tag === 0xa0 ? 1 : 0; // Skip explicit [0] version if present

    const serialNode = parts[i];
    const issuerNode = parts[i + 2];
    const subjectNode = parts[i + 4];

    // Format serial number as hex
    let serialHex = '';
    if (serialNode) {
      const sBytes = b.slice(serialNode.contentStart, serialNode.end);
      serialHex = Array.from(sBytes)
        .map(x => x.toString(16).padStart(2, '0'))
        .join(':')
        .toUpperCase();
    }

    return {
      issuer: parseName(b, issuerNode),
      subject: parseName(b, subjectNode),
      serial: serialHex,
      hasSct: hasExtension(b, tbs, SCT_EXTENSION_OID)
    };
  } catch (e) {
    console.error('Error parsing X.509 DER:', e);
    return null;
  }
}

// Вычисление SHA-256 хэша
async function computeSha256(buffer) {
  try {
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(':');
  } catch (e) {
    return '';
  }
}

// ===== 3. Анализ доверия и классификация =====

function formatName(obj) {
  if (!obj) return '(неизвестно)';
  return [obj.O, obj.CN].filter(Boolean).join(' / ') || obj.CN || obj.O || '(без имени)';
}

function checkMatch(name, list) {
  if (!name) return false;
  const n = name.toLowerCase();
  return list.some(item => n.includes(item.toLowerCase()));
}

async function analyzeSecurityInfo(si, url) {
  let isHttps = false;
  let hostname = '';
  try {
    const u = new URL(url);
    isHttps = u.protocol === 'https:' || u.protocol === 'wss:';
    hostname = u.hostname;
  } catch (e) { /* about:blank и прочее */ }

  // Браузер вообще не передал securityInfo. Это НЕ признак HTTP:
  // на https это значит, что флаг выключен или API недоступен.
  if (!si) {
    if (isHttps) {
      return {
        level: 'flag_required',
        badge: 'FLAG',
        badgeColor: '#eab308',
        iconTheme: 'warning',
        title: '⚠️ Нет доступа к сертификату.\nВключите chrome://flags/#web-request-security-info и перезапустите Chrome.',
        issuerName: 'Данные сертификата недоступны',
        subjectName: hostname,
        fingerprint: '',
        flagRequired: true,
        riskDescription: 'Chrome не передал расширению данные сертификата. Проверьте, что флаг chrome://flags/#web-request-security-info включён и браузер был полностью перезапущен.',
        certificates: []
      };
    }
    return {
      level: 'insecure',
      badge: 'HTTP',
      badgeColor: '#64748b',
      iconTheme: 'insecure',
      title: '🔓 Соединение не защищено (HTTP / Plaintext)',
      issuerName: 'Отсутствует (HTTP)',
      subjectName: hostname,
      fingerprint: '',
      riskDescription: 'Трафик передается в открытом виде без шифрования TLS. Данные могут перехватываться любым участником сети.',
      certificates: []
    };
  }

  // state === 'insecure' от самого Chrome — это действительно простой HTTP
  if (si.state === 'insecure') {
    return {
      level: 'insecure',
      badge: 'HTTP',
      badgeColor: '#64748b',
      iconTheme: 'insecure',
      title: '🔓 Соединение не защищено (HTTP / Plaintext)',
      issuerName: 'Отсутствует (HTTP)',
      subjectName: hostname,
      fingerprint: '',
      riskDescription: 'Трафик передается в открытом виде без шифрования TLS. Данные могут перехватываться любым участником сети.',
      certificates: []
    };
  }

  if (si.state === 'broken') {
    return {
      level: 'danger',
      badge: '!',
      badgeColor: '#dc2626',
      iconTheme: 'danger',
      title: '🚨 Ошибка сертификата: TLS-соединение скомпрометировано',
      issuerName: 'Недействительный сертификат',
      subjectName: hostname,
      fingerprint: '',
      riskDescription: 'Chrome отметил соединение как broken: сертификат просрочен, отозван, самоподписан или не соответствует домену.',
      certificates: []
    };
  }

  const certs = si.certificates || [];
  if (certs.length === 0) {
    return {
      level: 'warning',
      badge: '?',
      badgeColor: '#d97706',
      iconTheme: 'warning',
      title: '⚠️ TLS включен, но данные сертификата недоступны',
      issuerName: '(Не удалось прочитать)',
      subjectName: url ? new URL(url).hostname : '',
      fingerprint: '',
      riskDescription: 'Браузер установил TLS-соединение, но не предоставил сертификат расширению.',
      certificates: []
    };
  }

  const parsedChain = [];
  let sctFound = false;
  let parseFailed = false;
  let verifiedByHash = false;
  let matchedHashRoot = null;

  for (let idx = 0; idx < certs.length; idx++) {
    const c = certs[idx];
    let parsed = null;
    let fp = c.fingerprint?.sha256 || '';

    if (c.rawDER) {
      parsed = parseCertificate(c.rawDER);
      if (!fp) {
        fp = await computeSha256(c.rawDER);
      }
    }

    if (!parsed) parseFailed = true;
    if (parsed?.hasSct) sctFound = true;

    // Сверка с Chrome Root Store остаётся, но сработать может только если Chrome
    // однажды начнёт отдавать цепочку: сейчас приходит один лист, а в базе корни.
    if (fp && trustedRootsMap[fp]) {
      verifiedByHash = true;
      matchedHashRoot = trustedRootsMap[fp];
    }

    parsedChain.push({
      issuer: parsed?.issuer || {},
      subject: parsed?.subject || {},
      issuerStr: parsed ? formatName(parsed.issuer) : '',
      subjectStr: parsed ? formatName(parsed.subject) : '',
      serial: parsed?.serial || '',
      fingerprint: fp,
      hasSct: Boolean(parsed?.hasSct),
      verifiedByHash: Boolean(fp && trustedRootsMap[fp])
    });
  }

  const leaf = parsedChain[0] || { issuerStr: '', subjectStr: '', fingerprint: '' };
  const issuerName = leaf.issuerStr || '(без имени)';
  const subjectName = leaf.subjectStr || hostname;

  // Разобрать DER не удалось — судить не о чем, молчим вместо догадок.
  if (parseFailed) {
    return {
      level: 'warning',
      badge: '?',
      badgeColor: '#d97706',
      iconTheme: 'warning',
      title: '⚠️ Не удалось разобрать сертификат',
      issuerName: issuerName,
      subjectName: subjectName,
      fingerprint: leaf.fingerprint,
      riskDescription: 'Браузер передал сертификат, но его структуру не удалось разобрать. Проверка Certificate Transparency не выполнена.',
      certificates: parsedChain
    };
  }

  if (sctFound) {
    return {
      level: 'trusted',
      badge: 'OK',
      badgeColor: '#16a34a',
      iconTheme: 'trusted',
      title: '🛡️ Сертификат публичного УЦ\nИздатель: ' + issuerName + '\n✓ Есть подписи Certificate Transparency',
      issuerName: issuerName,
      subjectName: subjectName,
      fingerprint: leaf.fingerprint,
      verifiedByHash: verifiedByHash,
      matchedRoot: matchedHashRoot,
      hasSct: true,
      riskDescription: 'В сертификате есть подписи CT-логов (SCT). Их выдают только публично доверенным удостоверяющим центрам, поэтому локально установленный корень — антивирус, корпоративный DPI, государственный УЦ — такой сертификат подделать не может.',
      certificates: parsedChain
    };
  }

  // Издателя добавил сам пользователь — например, корпоративный внутренний УЦ.
  if (checkMatch(leaf.issuerStr, userWhitelist)) {
    return {
      level: 'trusted',
      badge: 'OK',
      badgeColor: '#16a34a',
      iconTheme: 'trusted',
      title: '🛡️ УЦ из вашего белого списка\nИздатель: ' + issuerName,
      issuerName: issuerName,
      subjectName: subjectName,
      fingerprint: leaf.fingerprint,
      hasSct: false,
      riskDescription: 'Подписей Certificate Transparency нет, но этот издатель добавлен вами в белый список вручную.',
      certificates: parsedChain
    };
  }

  return {
    level: 'danger',
    badge: '!',
    badgeColor: '#dc2626',
    iconTheme: 'danger',
    title: '🚨 Сертификат вне Certificate Transparency\nИздатель: ' + issuerName + '\nПодписан корнем, установленным локально!',
    issuerName: issuerName,
    subjectName: subjectName,
    fingerprint: leaf.fingerprint,
    hasSct: false,
    riskDescription: 'В сертификате нет подписей CT-логов. Публичные УЦ обязаны их проставлять, и получить их может только публично доверенный центр. Значит сертификат выпущен корнем, установленным на этом компьютере или в вашей сети: антивирус, корпоративный DPI или государственный перехват. Трафик расшифровывается третьей стороной.',
    certificates: parsedChain
  };
}

// ===== 4. Обновление интерфейса браузера (Тулбар) =====

function updateBrowserAction(tabId, data) {
  try {
    // Бейдж с текстом и цветом
    chrome.action.setBadgeText({ tabId, text: data.badge });
    chrome.action.setBadgeBackgroundColor({ tabId, color: data.badgeColor });

    if (chrome.action.setBadgeTextColor) {
      chrome.action.setBadgeTextColor({ tabId, color: '#ffffff' });
    }

    // Тултип при наведении
    chrome.action.setTitle({ tabId, title: data.title });

    // Динамическая иконка
    const theme = data.iconTheme || 'default';
    chrome.action.setIcon({
      tabId,
      path: {
        "16": `icons/icon-${theme}-16.png`,
        "32": `icons/icon-${theme}-32.png`,
        "48": `icons/icon-${theme}-48.png`
      }
    });
  } catch (e) {
    // Tab might have closed
  }
}

// ===== 5. Перехват заголовков webRequest с защитой от отсутствия флага =====

let isSecurityInfoSupported = true;
let securityInfoError = null;

chrome.webRequest.onBeforeRequest.addListener(
  details => {
    if (details.tabId >= 0 && details.type === 'main_frame') {
      // Навигация началась — прошлый статус этой вкладки больше не действителен.
      // Без этого popup показывал бы данные предыдущего сайта на новом домене.
      tabStatusMap.delete(details.tabId);
      chrome.storage.session.remove('tab_' + details.tabId).catch(() => {});

      // Предварительное состояние загрузки
      chrome.action.setBadgeText({ tabId: details.tabId, text: '...' });
      chrome.action.setBadgeBackgroundColor({ tabId: details.tabId, color: '#64748b' });
      chrome.action.setTitle({ tabId: details.tabId, title: 'Проверяю сертификат…' });
    }
  },
  { urls: ['<all_urls>'], types: ['main_frame'] }
);

function registerWebRequestListener() {
  try {
    chrome.webRequest.onHeadersReceived.addListener(
      async details => {
        const { tabId, url, securityInfo } = details;
        if (tabId < 0 || details.type !== 'main_frame') return;

        // Если Chrome передал securityInfo - флаг 100% включен!
        if (securityInfo && securityInfo.state) {
          securityInfoDeliveries++;
          if (!flagConfirmed) {
            flagConfirmed = true;
            chrome.storage.local.set({ flagConfirmed: true });
          }
        }

        const analysis = await analyzeSecurityInfo(securityInfo, url);

        // Значок обновляем СРАЗУ, до записи в storage: ждать завершения
        // асинхронной записи здесь значило задерживать появление статуса.
        tabStatusMap.set(tabId, { ...analysis, url, timestamp: Date.now() });
        updateBrowserAction(tabId, analysis);
        saveTabStatus(tabId, { ...analysis, url, timestamp: Date.now() });

        // Уведомляем контентный скрипт вкладки
        chrome.tabs.sendMessage(tabId, {
          type: 'CA_STATUS_UPDATE',
          payload: analysis
        }).catch(() => {});
      },
      { urls: ['<all_urls>'], types: ['main_frame'] },
      ['securityInfo', 'securityInfoRawDer']
    );
    isSecurityInfoSupported = true;
  } catch (err) {
    // Синхронное исключение бывает только на Chrome < 144, где схема API
    // вообще не знает значений securityInfo.
    isSecurityInfoSupported = false;
    securityInfoError = err?.message || String(err);
    console.warn('CA Indicator: securityInfo extraInfoSpec отвергнут браузером:', securityInfoError);
  }

  // Зондовый слушатель: регистрируется ВСЕГДА и без extraInfoSpec.
  // Он нужен потому, что при выключенной фиче Chromium не бросает исключение,
  // а лишь пишет ошибку в консоль и молча не регистрирует слушатель
  // (web_request_api.cc: AddMessageToConsoleForListener + return).
  // Значит try/catch выше сам по себе выключенный флаг обнаружить не может.
  chrome.webRequest.onHeadersReceived.addListener(
    details => {
      const { tabId, url } = details;
      if (tabId < 0 || details.type !== 'main_frame') return;

      let hostname = '';
      try {
        const u = new URL(url);
        if (u.protocol !== 'https:') return;
        hostname = u.hostname;
      } catch (e) {
        return;
      }

      httpsResponsesSeen++;

      // Самовосстановление: отметка о рабочем флаге стоит, но с момента запуска
      // воркера securityInfo не пришёл ни разу за несколько https-ответов —
      // значит флаг выключили. Иначе предупреждение уже никогда не вернулось бы.
      if (flagConfirmed && securityInfoDeliveries === 0 && httpsResponsesSeen >= 3) {
        flagConfirmed = false;
        chrome.storage.local.set({ flagConfirmed: false });
      }

      // securityInfo уже приходил — основной слушатель жив, не мешаем ему.
      if (flagConfirmed) return;

      // Не поднимаем тревогу на самом первом ответе: слушатели одного события
      // вызываются по порядку регистрации, дадим основному шанс отработать.
      if (httpsResponsesSeen < 2) return;

      const flagNotice = {
        level: 'flag_required',
        badge: 'FLAG',
        badgeColor: '#eab308',
        iconTheme: 'warning',
        title: '⚠️ Требуется включить флаг в Chrome:\nchrome://flags/#web-request-security-info',
        issuerName: 'Флаг не включен в браузере',
        subjectName: hostname,
        fingerprint: '',
        riskDescription: 'Chrome не передаёт расширению данные сертификата. Включите chrome://flags/#web-request-security-info и полностью перезапустите браузер.',
        flagRequired: true
      };

      saveTabStatus(tabId, { ...flagNotice, url, timestamp: Date.now() });
      updateBrowserAction(tabId, flagNotice);
    },
    { urls: ['<all_urls>'], types: ['main_frame'] }
  );
}

registerWebRequestListener();

// Очистка памяти при закрытии вкладки
chrome.tabs.onRemoved.addListener(tabId => {
  tabStatusMap.delete(tabId);
  chrome.storage.session.remove('tab_' + tabId).catch(() => {});
});

// ===== 6. Функция обновления базы из официального Chrome Root Store =====

async function updateRootStoreFromGoogle() {
  const url = 'https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/root_store.certs?format=TEXT';
  const response = await fetch(url);
  if (!response.ok) throw new Error('HTTP ' + response.status);
  const base64Data = await response.text();
  const binaryString = atob(base64Data);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  const pem = new TextDecoder().decode(bytes);
  const matches = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
  let newRoots = 0;
  const downloaded = {};

  for (const m of matches) {
    const b64 = m.replace(/-----[^\n]+-----/g, '').replace(/\s+/g, '');
    const bin = atob(b64);
    const der = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      der[i] = bin.charCodeAt(i);
    }
    const hashBuf = await crypto.subtle.digest('SHA-256', der);
    const hashHex = Array.from(new Uint8Array(hashBuf))
      .map(b => b.toString(16).padStart(2, '0').toUpperCase())
      .join(':');

    const parsed = parseCertificate(der);
    const name = [parsed?.subject?.O, parsed?.subject?.CN].filter(Boolean).join(' / ') || 'Google Root';
    downloaded[hashHex] = { name, source: 'Google Chrome Root Store (Online)' };
    newRoots++;
  }

  trustedRootsMap = { ...trustedRootsMap, ...downloaded };
  rootStoreUpdatedAt = new Date().toISOString();
  await chrome.storage.local.set({
    customRoots: downloaded,
    rootStoreUpdatedAt
  });

  return {
    success: true,
    count: Object.keys(trustedRootsMap).length,
    updatedCount: newRoots,
    updatedAt: rootStoreUpdatedAt
  };
}

// ===== 7. Обработка сообщений от Popup и Content Script =====

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_TAB_STATUS') {
    const tabId = message.tabId || sender?.tab?.id;
    loadTabStatus(tabId).then(status => {
      sendResponse({
        status,
        userWhitelist,
        flagConfirmed,
        // Флаг считается выключенным ТОЛЬКО если браузер уже отдавал https-ответы,
        // а securityInfo не пришёл ни разу. Пустой кэш статуса (уснувший service
        // worker) больше не трактуется как отсутствие флага.
        flagMissing: !flagConfirmed && (httpsResponsesSeen >= 2 || !isSecurityInfoSupported),
        isSecurityInfoSupported,
        securityInfoError,
        rootStoreInfo: {
          count: Object.keys(trustedRootsMap).length,
          updatedAt: rootStoreUpdatedAt
        }
      });
    });
    return true;
  }

  if (message.type === 'UPDATE_ROOT_STORE_FROM_GOOGLE') {
    updateRootStoreFromGoogle().then(res => {
      sendResponse(res);
    }).catch(err => {
      sendResponse({ success: false, error: err?.message || String(err) });
    });
    return true;
  }

  if (message.type === 'ADD_WHITELIST') {
    const caName = message.name?.trim();
    if (caName && !userWhitelist.includes(caName)) {
      userWhitelist.push(caName);
      chrome.storage.local.set({ userWhitelist }, () => {
        sendResponse({ success: true, userWhitelist });
      });
      return true;
    }
    sendResponse({ success: false });
    return true;
  }

  if (message.type === 'REMOVE_WHITELIST') {
    const caName = message.name;
    userWhitelist = userWhitelist.filter(x => x !== caName);
    chrome.storage.local.set({ userWhitelist }, () => {
      sendResponse({ success: true, userWhitelist });
    });
    return true;
  }
});

// ===== 8. Автообновление базы корневых УЦ из официального Chrome Root Store =====

const ROOT_STORE_ALARM = 'ca-indicator-root-store-update';
const ROOT_STORE_PERIOD_MINUTES = 60 * 24 * 7; // раз в неделю

function ensureRootStoreAlarm() {
  chrome.alarms.get(ROOT_STORE_ALARM, alarm => {
    if (!alarm) {
      chrome.alarms.create(ROOT_STORE_ALARM, {
        delayInMinutes: 1,
        periodInMinutes: ROOT_STORE_PERIOD_MINUTES
      });
    }
  });
}

chrome.runtime.onInstalled.addListener(ensureRootStoreAlarm);
chrome.runtime.onStartup.addListener(ensureRootStoreAlarm);

chrome.alarms.onAlarm.addListener(alarm => {
  if (alarm.name !== ROOT_STORE_ALARM) return;
  updateRootStoreFromGoogle()
    .then(r => console.log('CA Indicator: база корней обновлена, записей:', r.count))
    .catch(e => console.warn('CA Indicator: обновление базы не удалось:', e?.message || e));
});
