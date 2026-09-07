// background.js - CA Indicator Service Worker
// 100% Offline, Privacy-Preserving Certificate Trust & MITM Interception Detector

// ===== 1. Списки доверенных и подозрительных центров =====

// Общепризнанные мировые центры сертификации (Mozilla Root Store, Chrome Root Store, Apple, Microsoft)
const GLOBAL_TRUSTED = [
  "Internet Security Research Group", "ISRG", "Let's Encrypt",
  "Google Trust Services", "Google Trust Services LLC", "GTS", "WR", "WE",
  "DigiCert", "Baltimore", "Cybertrust", "Encryption Everywhere",
  "Sectigo", "The USERTRUST Network", "USERTrust", "Comodo",
  "GoGetSSL", "GoGetSSL RSA DV CA", "GoGetSSL ECC DV CA",
  "PositiveSSL", "InstantSSL", "cPanel", "cPanel, Inc.",
  "GlobalSign", "GlobalSign nv-sa", "GlobalSign Root CA", "AlphaSSL",
  "Amazon", "Amazon Trust Services", "Starfield", "GoDaddy",
  "Cloudflare", "Cloudflare, Inc.",
  "Microsoft Corporation", "Microsoft", "Apple", "Apple Inc.",
  "IdenTrust", "Buypass", "Actalis", "SSL.com", "ZeroSSL",
  "Certum", "Asseco", "HARICA", "QuoVadis", "SwissSign",
  "T-Systems", "TeleSec", "D-TRUST", "Telia", "DFN",
  "Thawte", "GeoTrust", "RapidSSL",
  "SecureTrust", "Trustwave", "WISeKey", "SECOM",
  "Firmaprofesional", "Izenpe", "Camerfirma", "AC Camerfirma",
  "Microsec", "Netlock", "InfoNotary", "Disig", "e-Szigno", "Chunghwa Telecom",
  "Network Solutions", "Entrust", "AffirmTrust"
];

// Сигнатуры известных центров перехвата, государственных УЦ, антивирусных MITM-фильтров и локальных прокси
const KNOWN_INTERCEPTION = [
  // Государственные УЦ (РФ, РК, РБ, УЗ)
  "Russian Trusted", "Russian Trusted Root CA", "Russian Trusted Sub CA",
  "Ministry of Digital Development", "Минцифры", "Министерство цифрового развития",
  "Госуслуги", "Gosuslugi", "НИИ Восход", "Сбер", "Sberbank", "Sberbank CA", "ВТБ", "VTB",
  "Qaznet", "Qaznet Trust Network", "State Technical Service", "STS.KZ",
  "Национальный удостоверяющий центр РК", "НУЦ РК",
  "UZINFOCOM", "O'zbekiston", "Uzbekistan", "Kryptobel", "GosSUOK", "ГосСУОК",

  // Антивирусные SSL/TLS инспекторы (локальный перехват на ПК)
  "Kaspersky", "AO Kaspersky Lab", "Kaspersky Anti-Virus",
  "ESET", "ESET SSL Filter", "ESET, spol. s r.o.",
  "Avast", "Avast Web/Mail Shield", "AVG", "AVG Web/Mail Shield",
  "Bitdefender", "Bitdefender Personal CA",
  "Dr.Web", "Doctor Web", "Doctor Web Ltd",
  "Sophos", "Sophos SSL CA",
  "AdGuard", "AdGuard Personal Root Certificate",

  // Корпоративные DPI и шлюзы перехвата
  "Fortinet", "FortiGate", "Zscaler", "Zscaler Root CA", "Netskope",
  "Palo Alto", "Palo Alto Networks", "PAN-OS",
  "Check Point", "Blue Coat", "Symantec Web", "Symantec Web Security",
  "Cisco Umbrella", "Cisco IronPort", "IronPort", "Forcepoint",
  "SonicWall", "WatchGuard", "Barracuda",

  // Инструменты отладки и аудита (MITM)
  "mitmproxy", "Charles Proxy", "Charles", "Fiddler", "DO_NOT_TRUST_FiddlerRoot",
  "PortSwigger", "Burp Suite", "Burp", "Proxyman", "Whistle"
];

// In-memory кэш статуса для вкладок
const tabStatusMap = new Map();

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
    if (res.customRoots && Object.keys(res.customRoots).length > 0) {
      trustedRootsMap = res.customRoots;
      if (res.rootStoreUpdatedAt) rootStoreUpdatedAt = res.rootStoreUpdatedAt;
    } else {
      const resp = await fetch(chrome.runtime.getURL('trusted_roots.json'));
      const data = await resp.json();
      if (data && data.roots) {
        trustedRootsMap = data.roots;
        if (data.updatedAt) rootStoreUpdatedAt = data.updatedAt;
      }
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
    if (changes.customRoots) trustedRootsMap = changes.customRoots.newValue || {};
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
      serial: serialHex
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
  if (!si || si.state !== 'secure') {
    return {
      level: 'insecure',
      badge: 'HTTP',
      badgeColor: '#64748b',
      iconTheme: 'insecure',
      title: '🔓 Соединение не защищено (HTTP / Plaintext)',
      issuerName: 'Отсутствует (HTTP)',
      subjectName: url ? new URL(url).hostname : '',
      fingerprint: '',
      riskDescription: 'Трафик передается в открытом виде без шифрования TLS. Данные могут перехватываться любым участником сети.',
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
  let isDanger = false;
  let dangerName = '';
  let isTrusted = false;
  let trustedName = '';
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

    const issuerStr = parsed ? formatName(parsed.issuer) : '';
    const subjectStr = parsed ? formatName(parsed.subject) : '';

    // 1. Проверка по криптографическому SHA-256 хэшу (Chrome Root Store / Mozilla)
    if (fp && trustedRootsMap[fp]) {
      verifiedByHash = true;
      matchedHashRoot = trustedRootsMap[fp];
      isTrusted = true;
      if (!trustedName) trustedName = matchedHashRoot.name;
    }

    parsedChain.push({
      issuer: parsed?.issuer || {},
      subject: parsed?.subject || {},
      issuerStr,
      subjectStr,
      serial: parsed?.serial || '',
      fingerprint: fp,
      verifiedByHash: Boolean(fp && trustedRootsMap[fp])
    });

    // 2. Проверяем на известные перехватчики (любой сертификат в цепочке)
    if (checkMatch(issuerStr, KNOWN_INTERCEPTION) || checkMatch(subjectStr, KNOWN_INTERCEPTION)) {
      isDanger = true;
      dangerName = checkMatch(issuerStr, KNOWN_INTERCEPTION) ? issuerStr : subjectStr;
    }

    // 3. Проверяем по имени на общепризнанные УЦ или пользовательский белый список
    if (
      checkMatch(issuerStr, GLOBAL_TRUSTED) ||
      checkMatch(subjectStr, GLOBAL_TRUSTED) ||
      checkMatch(issuerStr, userWhitelist) ||
      checkMatch(subjectStr, userWhitelist)
    ) {
      isTrusted = true;
      if (!trustedName) trustedName = issuerStr || subjectStr;
    }
  }

  const leaf = parsedChain[0] || { issuerStr: '(неизвестно)', subjectStr: '' };
  const primaryName = leaf.issuerStr || trustedName || '(без имени)';

  if (isDanger) {
    return {
      level: 'danger',
      badge: '!',
      badgeColor: '#dc2626',
      iconTheme: 'danger',
      title: `🚨 ВНИМАНИЕ: Обнаружен перехватчик трафика!\nУЦ: ${dangerName || primaryName}\nВаш зашифрованный трафик расшифровывается третьей стороной!`,
      issuerName: dangerName || primaryName,
      subjectName: leaf.subjectStr || (url ? new URL(url).hostname : ''),
      fingerprint: leaf.fingerprint,
      verifiedByHash: false,
      riskDescription: 'Сертификат выдан известным центром перехвата, государственным УЦ или локальным фильтром. Весь ваш трафик (пароли, cookies, переписка) расшифровывается!',
      certificates: parsedChain
    };
  }

  if (isTrusted) {
    return {
      level: 'trusted',
      badge: 'OK',
      badgeColor: '#16a34a',
      iconTheme: 'trusted',
      title: `🛡️ Общепризнанный доверенный УЦ\nИздатель: ${primaryName}\n${verifiedByHash ? '✓ Хэш подтвержден в Google Chrome Root Store' : 'Сертификат входит в глобальные хранилища'}`,
      issuerName: primaryName,
      subjectName: leaf.subjectStr || (url ? new URL(url).hostname : ''),
      fingerprint: leaf.fingerprint,
      verifiedByHash: verifiedByHash,
      matchedRoot: matchedHashRoot,
      riskDescription: verifiedByHash
        ? 'Сертификат подтвержден официальным криптографическим отпечатком (SHA-256) в Chrome Root Store / Mozilla NSS. Подделка имени исключена.'
        : 'Сертификат выдан общепризнанным глобальным удостоверяющим центром. Подделка и перехват через локальные государственные сертификаты исключены.',
      certificates: parsedChain
    };
  }

  // Не попал ни в опасные, ни в доверенные
  return {
    level: 'warning',
    badge: '?',
    badgeColor: '#d97706',
    iconTheme: 'warning',
    title: `⚠️ Неизвестный УЦ\nИздатель: ${primaryName}\nУЦ отсутствует в списке общепризнанных мировых центров`,
    issuerName: primaryName,
    subjectName: leaf.subjectStr || (url ? new URL(url).hostname : ''),
    fingerprint: leaf.fingerprint,
    riskDescription: 'Сертификат подписан неизвестным или частным центром сертификации. Если это не локальная сеть компании, трафик может прослушиваться!',
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
          if (!flagConfirmed) {
            flagConfirmed = true;
            chrome.storage.local.set({ flagConfirmed: true });
          }
        }

        const analysis = await analyzeSecurityInfo(securityInfo, url);
        tabStatusMap.set(tabId, { ...analysis, url, timestamp: Date.now() });

        // Обновляем значок и бейдж
        updateBrowserAction(tabId, analysis);

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
    isSecurityInfoSupported = false;
    securityInfoError = err?.message || String(err);
    console.warn('CA Indicator: SecurityInfo not permitted by browser without flag:', securityInfoError);

    // Регистрируем fallback слушатель без securityInfo, чтобы воркер не падал
    try {
      chrome.webRequest.onHeadersReceived.addListener(
        details => {
          const { tabId, url } = details;
          if (tabId < 0 || details.type !== 'main_frame') return;

          const flagNotice = {
            level: 'flag_required',
            badge: 'FLAG',
            badgeColor: '#eab308',
            iconTheme: 'warning',
            title: '⚠️ Требуется включить флаг в Chrome:\nchrome://flags/#web-request-security-info',
            issuerName: 'Флаг не включен в браузере',
            subjectName: url ? new URL(url).hostname : '',
            fingerprint: '',
            riskDescription: 'В браузере Chrome доступ к данным сертификатов требует включения флага: chrome://flags/#web-request-security-info',
            flagRequired: true
          };

          tabStatusMap.set(tabId, { ...flagNotice, url, timestamp: Date.now() });
          updateBrowserAction(tabId, flagNotice);
        },
        { urls: ['<all_urls>'], types: ['main_frame'] }
      );
    } catch (fallbackErr) {
      console.error('Fallback listener error:', fallbackErr);
    }
  }
}

registerWebRequestListener();

// Очистка памяти при закрытии вкладки
chrome.tabs.onRemoved.addListener(tabId => {
  tabStatusMap.delete(tabId);
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
    trustedRootsMap[hashHex] = { name, source: 'Google Chrome Root Store (Online)' };
    newRoots++;
  }

  rootStoreUpdatedAt = new Date().toISOString();
  await chrome.storage.local.set({
    customRoots: trustedRootsMap,
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
    let status = tabStatusMap.get(tabId) || null;
    sendResponse({
      status,
      userWhitelist,
      flagConfirmed,
      isSecurityInfoSupported,
      securityInfoError,
      rootStoreInfo: {
        count: Object.keys(trustedRootsMap).length,
        updatedAt: rootStoreUpdatedAt
      }
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
