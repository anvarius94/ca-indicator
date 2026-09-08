// popup.js - CA Trust Indicator User Interface Logic

document.addEventListener('DOMContentLoaded', async () => {
  const elSiteDomain = document.getElementById('site-domain');
  const elStatusCard = document.getElementById('status-card');
  const elStatusIcon = document.getElementById('status-icon');
  const elLevelBadge = document.getElementById('status-level-badge');
  const elHeadline = document.getElementById('status-headline');
  const elDesc = document.getElementById('status-description');
  const elIssuer = document.getElementById('detail-issuer');
  const elSubject = document.getElementById('detail-subject');
  const elFingerprint = document.getElementById('detail-fingerprint');
  const btnCopyFp = document.getElementById('btn-copy-fp');
  const btnWhitelist = document.getElementById('btn-whitelist');
  const selectBannerMode = document.getElementById('select-banner-mode');
  const selectBannerPos = document.getElementById('select-banner-pos');
  const elWhitelistItems = document.getElementById('whitelist-items');
  const elFlagAlert = document.getElementById('flag-alert');
  const btnCopyFlag = document.getElementById('btn-copy-flag');
  const btnReload = document.getElementById('btn-reload-page');
  const elHashBadge = document.getElementById('badge-hash-verified');
  const elRootCount = document.getElementById('rootstore-count');
  const elRootDate = document.getElementById('rootstore-date');
  const btnUpdateRoots = document.getElementById('btn-update-roots');
  const elAiaSection = document.getElementById('aia-section');
  const elAiaLoader = document.getElementById('aia-loader');
  const elAiaVerdict = document.getElementById('aia-verdict');
  const elAiaChain = document.getElementById('aia-chain');
  const btnCopyReport = document.getElementById('btn-copy-report');

  // Последний результат перепроверки — попадает в отчёт
  let lastAia = null;

  let currentTabStatus = null;
  let currentHost = '';
  let currentWhitelist = [];

  // 1. Load preferences
  chrome.storage.local.get(['bannerMode', 'bannerPosition', 'userWhitelist'], res => {
    if (res.bannerMode) selectBannerMode.value = res.bannerMode;
    if (res.bannerPosition) selectBannerPos.value = res.bannerPosition;
    if (Array.isArray(res.userWhitelist)) {
      currentWhitelist = res.userWhitelist;
      renderWhitelist(currentWhitelist);
    }
  });

  // Settings change handlers
  selectBannerMode.addEventListener('change', () => {
    chrome.storage.local.set({ bannerMode: selectBannerMode.value });
  });

  selectBannerPos.addEventListener('change', () => {
    chrome.storage.local.set({ bannerPosition: selectBannerPos.value });
  });

  // 2. Identify active tab and request analysis
  const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!activeTab) {
    showError('Не удалось определить активную вкладку.');
    return;
  }

  // Домены, на которых Chrome вообще не пускает расширения: webRequest там
  // не срабатывает никогда, поэтому статуса быть не может в принципе.
  function isRestrictedUrl(urlObj) {
    if (urlObj.hostname === 'chromewebstore.google.com') return true;
    if (urlObj.hostname === 'chrome.google.com' && urlObj.pathname.startsWith('/webstore')) return true;
    return false;
  }

  function sameOrigin(a, b) {
    try {
      return new URL(a).origin === new URL(b).origin;
    } catch (e) {
      return false;
    }
  }

  try {
    const urlObj = new URL(activeTab.url);
    currentHost = urlObj.hostname;
    elSiteDomain.textContent = urlObj.hostname || activeTab.url;

    if (urlObj.protocol === 'chrome:' || urlObj.protocol === 'edge:' || urlObj.protocol === 'about:') {
      renderInternalPage(urlObj.hostname);
      return;
    }

    if (isRestrictedUrl(urlObj)) {
      renderRestrictedPage(urlObj.hostname);
      return;
    }
  } catch (e) {
    elSiteDomain.textContent = activeTab.url || 'Неизвестно';
  }

  const btnOpenFlags = document.getElementById('btn-open-flags');
  if (btnOpenFlags) {
    btnOpenFlags.addEventListener('click', async () => {
      const flagsUrl = 'chrome://flags/#web-request-security-info';
      try {
        await navigator.clipboard.writeText(flagsUrl);
      } catch (e) {}

      chrome.tabs.create({ url: flagsUrl }, () => {
        if (chrome.runtime.lastError) {
          btnOpenFlags.textContent = 'Скопировано! Вставьте в новой вкладке (Ctrl+V) ✓';
          chrome.tabs.create({ url: 'chrome://newtab' }, () => {});
          setTimeout(() => {
            btnOpenFlags.textContent = '🚀 Открыть chrome://flags';
          }, 4000);
        } else {
          btnOpenFlags.textContent = 'Открыто! ✓';
        }
      });
    });
  }

  if (btnCopyFlag) {
    btnCopyFlag.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText('chrome://flags/#web-request-security-info');
        const orig = btnCopyFlag.textContent;
        btnCopyFlag.textContent = 'Скопировано! ✓';
        setTimeout(() => { btnCopyFlag.textContent = orig; }, 2000);
      } catch (e) {
        // Fallback
      }
    });
  }

  // Запрос статуса у фонового воркера
  chrome.runtime.sendMessage({ type: 'GET_TAB_STATUS', tabId: activeTab.id }, response => {
    if (chrome.runtime.lastError || !response) {
      renderFallback(activeTab.url, false);
      return;
    }

    // Баннер про флаг показывается ТОЛЬКО если фон уже видел https-ответы,
    // но securityInfo не пришёл ни разу. Пустой кэш статуса (уснувший service
    // worker) больше не считается признаком выключенного флага.
    const flagMissing = Boolean(response.flagMissing);
    if (elFlagAlert) elFlagAlert.style.display = flagMissing ? 'flex' : 'none';

    if (response.rootStoreInfo) renderRootStoreInfo(response.rootStoreInfo);

    if (response.userWhitelist) {
      currentWhitelist = response.userWhitelist;
      renderWhitelist(currentWhitelist);
    }

    // Статус обязан относиться к ТОМУ ЖЕ происхождению, что открыто во вкладке.
    // На заблокированных для расширений доменах webRequest не срабатывает,
    // и без этой проверки popup показывал бы сертификат предыдущего сайта.
    if (!response.status || !sameOrigin(response.status.url, activeTab.url)) {
      renderFallback(activeTab.url, flagMissing);
      return;
    }

    currentTabStatus = response.status;
    renderStatus(currentTabStatus);

    // Сетевые запросы уходят только теперь, когда пользователь открыл попап.
    if (currentTabStatus.leafDerB64) startAiaVerification(activeTab.id);
  });

  const AIA_OUTCOMES = {
    'no-aia-on-leaf': ['bad', 'У сертификата нет ссылки на издателя (AIA). Публичные УЦ её всегда указывают — почти наверняка сертификат выпущен корнем, установленным локально.'],
    'no-aia': ['unknown', 'Промежуточный УЦ не публикует ссылку на свой корень, и подходящего корня нет в базе. Цепочку до конца достроить не удалось.'],
    'fetch-failed': ['unknown', 'Сертификат издателя не удалось скачать: нет сети или сервер УЦ недоступен.'],
    'not-a-certificate': ['unknown', 'По ссылке издателя пришёл не сертификат.'],
    'depth-exceeded': ['unknown', 'Цепочка оказалась длиннее допустимой глубины.']
  };

  function startAiaVerification(tabId) {
    elAiaSection.style.display = 'block';
    elAiaLoader.style.display = 'flex';
    elAiaVerdict.style.display = 'none';
    elAiaChain.innerHTML = '';

    chrome.runtime.sendMessage({ type: 'VERIFY_CHAIN_AIA', tabId }, res => {
      elAiaLoader.style.display = 'none';
      elAiaVerdict.style.display = 'block';

      if (chrome.runtime.lastError || !res || !res.success) {
        elAiaVerdict.className = 'aia-verdict unknown';
        elAiaVerdict.textContent = 'Перепроверка не выполнена: ' +
          ((res && res.error) || (chrome.runtime.lastError && chrome.runtime.lastError.message) || 'нет ответа');
        return;
      }

      lastAia = res;

      const root = res.chain.find(c => c.knownRootName);
      if (res.trusted && root) {
        elAiaVerdict.className = 'aia-verdict ok';
        elAiaVerdict.textContent = 'Цепочка достроена до корня «' + root.knownRootName +
          '» из базы (' + (root.knownRootSource || 'корневое хранилище') +
          '). Все подписи в цепочке проверены криптографически.';
      } else if (res.anyBroken) {
        elAiaVerdict.className = 'aia-verdict bad';
        elAiaVerdict.textContent = 'Подпись в цепочке не сходится: сертификат подписан не тем ключом, который заявлен. Это прямой признак подмены.';
      } else if (currentTabStatus && currentTabStatus.whitelisted) {
        // Для сертификата, разрешённого вручную, отсутствие AIA и цепочки —
        // ожидаемая норма, а не тревога. Красный вердикт под зелёной карточкой
        // только сбивал бы с толку.
        elAiaVerdict.className = 'aia-verdict unknown';
        elAiaVerdict.textContent = res.outcome === 'no-aia-on-leaf'
          ? 'Цепочки нет: сертификат не ссылается на издателя и ни к какому публичному корню не ведёт. Для сертификата, который вы разрешили вручную, это нормально.'
          : 'Цепочку до публичного корня достроить не удалось — для сертификата, разрешённого вручную, это ожидаемо.';
      } else {
        const [cls, text] = AIA_OUTCOMES[res.outcome] || ['unknown', 'Результат неизвестен.'];
        elAiaVerdict.className = 'aia-verdict ' + cls;
        elAiaVerdict.textContent = text;
      }

      res.chain.forEach(c => {
        const li = document.createElement('li');
        const mark = document.createElement('span');
        mark.className = 'aia-mark';
        mark.textContent = c.signatureVerified === true ? '\u2713'
          : c.signatureVerified === false ? '\u2715'
          : c.knownRootName ? '\u2691' : '\u00b7';
        const name = document.createElement('span');
        name.className = 'aia-name' + (c.knownRootName ? ' aia-root' : '');
        name.textContent = c.subject + (c.knownRootName ? ' — корень из базы' : '');
        li.appendChild(mark);
        li.appendChild(name);
        elAiaChain.appendChild(li);
      });
    });
  }

  function renderRootStoreInfo(info) {
    if (elRootCount) elRootCount.textContent = info.count ?? '—';
    if (elRootDate) {
      let d = '—';
      if (info.updatedAt) {
        const parsed = new Date(info.updatedAt);
        d = isNaN(parsed) ? String(info.updatedAt) : parsed.toLocaleDateString();
      }
      elRootDate.textContent = d;
    }
  }

  function renderStatus(status) {
    elStatusCard.className = `status-card status-${status.level || 'warning'}`;
    if (elHashBadge) elHashBadge.style.display = status.hasSct ? 'block' : 'none';
    if (btnReload) btnReload.style.display = 'none';
    elIssuer.textContent = status.issuerName || '(неизвестно)';
    elSubject.textContent = status.subjectName || elSiteDomain.textContent;
    elFingerprint.textContent = status.fingerprint || 'Не вычислен';

    if (status.level === 'flag_required') {
      if (elFlagAlert) elFlagAlert.style.display = 'flex';
      elStatusIcon.textContent = '⚙️';
      elLevelBadge.textContent = 'ТРЕБУЕТСЯ ФЛАГ';
      elHeadline.textContent = 'Включите флаг в Chrome';
      elDesc.textContent = status.riskDescription || 'Включите флаг chrome://flags/#web-request-security-info и перезапустите браузер.';
      btnWhitelist.style.display = 'none';
    } else if (status.level === 'danger') {
      if (elFlagAlert) elFlagAlert.style.display = 'none';
      elStatusIcon.textContent = '🚨';
      // Этот уровень теперь возникает только при si.state === 'broken'.
      // Текст про отсутствие CT остался от v1.5.0 и вводил в заблуждение:
      // просроченный сертификат — не то же самое, что перехват трафика.
      elLevelBadge.textContent = 'НЕДЕЙСТВИТЕЛЬНЫЙ СЕРТИФИКАТ';
      elHeadline.textContent = 'Chrome забраковал сертификат';
      elDesc.textContent = status.riskDescription || 'Сертификат просрочен, отозван, самоподписан или выдан не на этот домен.';
    } else if (status.level === 'trusted') {
      if (elFlagAlert) elFlagAlert.style.display = 'none';
      if (status.whitelisted) {
        // Публичным этот УЦ не является и подписей CT у него нет: доверие
        // держится только на вашем решении и только для этого домена.
        elStatusIcon.textContent = '👤';
        elLevelBadge.textContent = 'РАЗРЕШЕНО ВАМИ';
        elHeadline.textContent = 'Исключение для этого домена';
      } else {
        elStatusIcon.textContent = '🛡️';
        elLevelBadge.textContent = 'ПУБЛИЧНЫЙ УЦ · CT';
        elHeadline.textContent = 'Соединение доверенное';
      }
      elDesc.textContent = status.riskDescription || 'В сертификате есть подписи Certificate Transparency.';
    } else if (status.level === 'warning') {
      elStatusIcon.textContent = '⚠️';
      if (status.parseFailed) {
        elLevelBadge.textContent = 'СЕРТИФИКАТ НЕ РАЗОБРАН';
        elHeadline.textContent = 'Проверка не выполнена';
      } else {
        // Основной случай: сертификат разобран, подписей CT в нём нет.
        // Говорить здесь «проверка не выполнена» — прямая неправда: проверка
        // выполнена, и результат её как раз тревожный.
        elLevelBadge.textContent = 'БЕЗ CERTIFICATE TRANSPARENCY';
        elHeadline.textContent = 'Возможен перехват трафика';
      }
      elDesc.textContent = status.riskDescription || 'Структуру сертификата не удалось разобрать, проверка Certificate Transparency не проводилась.';
    } else if (status.level === 'insecure') {
      if (elFlagAlert) elFlagAlert.style.display = 'none';
      elStatusIcon.textContent = '🔓';
      elLevelBadge.textContent = 'НЕТ ШИФРОВАНИЯ';
      elHeadline.textContent = 'Открытое соединение HTTP';
      elDesc.textContent = 'Данные передаются в незашифрованном виде. Любой посредник может их перехватить.';
    }

    // Разрешить можно только конкретный сертификат на конкретном домене,
    // поэтому без отпечатка кнопка не имеет смысла.
    const canWhitelist = Boolean(status.fingerprint) && !status.whitelisted &&
      (status.level === 'warning' || status.level === 'danger');
    btnWhitelist.style.display = canWhitelist ? 'block' : 'none';
  }

  function renderRestrictedPage(name) {
    if (elFlagAlert) elFlagAlert.style.display = 'none';
    if (btnReload) btnReload.style.display = 'none';
    elStatusCard.className = 'status-card status-loading';
    elStatusIcon.textContent = '🚫';
    elLevelBadge.textContent = 'ДОСТУП ЗАКРЫТ БРАУЗЕРОМ';
    elHeadline.textContent = 'Chrome не пускает сюда расширения';
    elDesc.textContent = 'На доменах Chrome Web Store браузер блокирует работу расширений, поэтому прочитать сертификат этой страницы невозможно. Это ограничение Chrome, а не признак угрозы.';
    elIssuer.textContent = 'Недоступно';
    elSubject.textContent = name;
    elFingerprint.textContent = '—';
  }

  function renderInternalPage(name) {
    if (elFlagAlert) elFlagAlert.style.display = 'none';
    elStatusCard.className = 'status-card status-trusted';
    elStatusIcon.textContent = 'ℹ️';
    elLevelBadge.textContent = 'СИСТЕМНАЯ СТРАНИЦА';
    elHeadline.textContent = 'Внутренний ресурс браузера';
    elDesc.textContent = 'Страница обслуживается самим браузером, внешние сертификаты не используются.';
    elIssuer.textContent = 'Локальный браузер';
    elSubject.textContent = name;
    elFingerprint.textContent = '—';
  }

  function renderFallback(url, flagMissing) {
    if (btnReload) btnReload.style.display = 'none';

    if (url && url.startsWith('http://')) {
      renderStatus({
        level: 'insecure',
        issuerName: 'Отсутствует (HTTP)',
        subjectName: elSiteDomain.textContent,
        fingerprint: '—',
        riskDescription: 'Страница загружена по незащищенному протоколу HTTP.'
      });
      return;
    }

    if (flagMissing) {
      if (elFlagAlert) elFlagAlert.style.display = 'flex';
      elStatusCard.className = 'status-card status-warning';
      elStatusIcon.textContent = '⚙️';
      elLevelBadge.textContent = 'ТРЕБУЕТСЯ НАСТРОЙКА CHROME';
      elHeadline.textContent = 'Включите флаг WebRequestSecurityInfo';
      elDesc.textContent = 'Chrome блокирует чтение сертификатов без флага. Скопируйте ссылку выше, переключите в Enabled и полностью перезапустите браузер.';
      elIssuer.textContent = 'Ожидание флага…';
      elSubject.textContent = elSiteDomain.textContent;
      return;
    }

    // Данных по вкладке просто нет: страница была открыта раньше, чем расширение
    // начало слушать запросы (установка или перезагрузка расширения).
    elStatusCard.className = 'status-card status-loading';
    elStatusIcon.textContent = '🔄';
    elLevelBadge.textContent = 'НЕТ ДАННЫХ';
    elHeadline.textContent = 'Обновите страницу';
    elDesc.textContent = 'Сертификат считывается в момент загрузки страницы. Эта вкладка была открыта раньше, чем расширение начало слушать запросы.';
    elIssuer.textContent = '—';
    elSubject.textContent = elSiteDomain.textContent;
    elFingerprint.textContent = '—';

    if (btnReload) {
      btnReload.style.display = 'block';
      btnReload.onclick = () => {
        chrome.tabs.reload(activeTab.id);
        window.close();
      };
    }
  }

  function showError(msg) {
    elStatusCard.className = 'status-card status-danger';
    elHeadline.textContent = 'Ошибка';
    elDesc.textContent = msg;
  }

  // Copy fingerprint
  btnCopyFp.addEventListener('click', async () => {
    const text = elFingerprint.textContent;
    if (text && text !== '—' && text !== 'Не вычислен') {
      try {
        await navigator.clipboard.writeText(text);
        const orig = btnCopyFp.textContent;
        btnCopyFp.textContent = '✓';
        setTimeout(() => { btnCopyFp.textContent = orig; }, 1500);
      } catch (e) {
        // Fallback copy
      }
    }
  });

  // Доверие выдаётся паре «этот домен + этот сертификат»
  btnWhitelist.addEventListener('click', () => {
    if (!currentTabStatus || !currentTabStatus.fingerprint || !currentHost) return;
    chrome.runtime.sendMessage({
      type: 'ADD_WHITELIST',
      host: currentHost,
      fingerprint: currentTabStatus.fingerprint,
      issuer: currentTabStatus.issuerName || '',
      tabId: activeTab.id
    }, res => {
      if (!res || !res.success) return;
      currentWhitelist = res.userWhitelist;
      renderWhitelist(currentWhitelist);
      currentTabStatus.level = 'trusted';
      currentTabStatus.whitelisted = true;
      currentTabStatus.riskDescription =
        'Вы сами разрешили этот сертификат для домена ' + currentHost + '. На других доменах он доверенным не считается.';
      renderStatus(currentTabStatus);
    });
  });

  function renderWhitelist(list) {
    elWhitelistItems.innerHTML = '';
    if (list.length === 0) {
      elWhitelistItems.innerHTML = '<li style="color: var(--text-muted); font-style: italic;">Список пуст</li>';
      return;
    }

    list.forEach(entry => {
      const li = document.createElement('li');

      const text = document.createElement('span');
      text.className = 'wl-entry';
      const host = document.createElement('strong');
      host.textContent = entry.host;
      text.appendChild(host);
      if (entry.issuer) {
        const issuer = document.createElement('span');
        issuer.className = 'wl-issuer';
        issuer.textContent = ' — ' + entry.issuer;
        text.appendChild(issuer);
      }
      li.appendChild(text);

      const btnDel = document.createElement('button');
      btnDel.className = 'btn-remove-wl';
      btnDel.textContent = '✕';
      btnDel.title = 'Отозвать доверие для ' + entry.host;
      btnDel.addEventListener('click', () => {
        chrome.runtime.sendMessage({
          type: 'REMOVE_WHITELIST',
          host: entry.host,
          fingerprint: entry.fingerprint,
          tabId: activeTab.id
        }, res => {
          if (res && res.userWhitelist) {
            currentWhitelist = res.userWhitelist;
            renderWhitelist(currentWhitelist);
          }
        });
      });
      li.appendChild(btnDel);
      elWhitelistItems.appendChild(li);
    });
  }

  // Отчёт простым текстом: удобно вставить в переписку или в чат с ИИ
  function buildReport() {
    const L = [];
    L.push('CA Trust Indicator v' + chrome.runtime.getManifest().version + ' — отчёт о сертификате');
    L.push('Сайт: ' + elSiteDomain.textContent);
    L.push('Вердикт: ' + elLevelBadge.textContent + ' — ' + elHeadline.textContent);
    L.push('Издатель: ' + elIssuer.textContent);
    L.push('Для домена: ' + elSubject.textContent);
    L.push('SHA-256: ' + elFingerprint.textContent);
    L.push('');
    L.push('Пояснение: ' + elDesc.textContent);

    if (lastAia) {
      L.push('');
      L.push('Перепроверка цепочки по AIA:');
      L.push('  ' + (elAiaVerdict.textContent || '—'));
      if (lastAia.chain && lastAia.chain.length) {
        L.push('  Цепочка:');
        lastAia.chain.forEach((c, i) => {
          const sig = c.signatureVerified === true ? 'подпись проверена'
            : c.signatureVerified === false ? 'ПОДПИСЬ НЕ СХОДИТСЯ'
            : c.knownRootName ? 'корень из базы' : 'подпись не проверялась';
          L.push('    ' + (i + 1) + '. ' + c.subject + '  [' + sig + ']');
          L.push('       SHA-256: ' + c.fingerprint);
        });
      }
    }
    return L.join('\n');
  }

  if (btnCopyReport) {
    btnCopyReport.addEventListener('click', async () => {
      const orig = btnCopyReport.textContent;
      try {
        await navigator.clipboard.writeText(buildReport());
        btnCopyReport.textContent = '\u2713 Отчёт скопирован';
      } catch (e) {
        btnCopyReport.textContent = '\u2715 Не удалось скопировать';
      }
      setTimeout(() => { btnCopyReport.textContent = orig; }, 2000);
    });
  }

  // Ручное обновление базы корневых УЦ из Chrome Root Store
  if (btnUpdateRoots) {
    btnUpdateRoots.addEventListener('click', () => {
      const orig = btnUpdateRoots.textContent;
      btnUpdateRoots.disabled = true;
      btnUpdateRoots.textContent = '⏳ Скачиваю…';
      chrome.runtime.sendMessage({ type: 'UPDATE_ROOT_STORE_FROM_GOOGLE' }, res => {
        btnUpdateRoots.disabled = false;
        if (res && res.success) {
          btnUpdateRoots.textContent = '✓ Загружено ' + res.updatedCount + ', всего ' + res.count;
          renderRootStoreInfo({ count: res.count, updatedAt: res.updatedAt });
        } else {
          btnUpdateRoots.textContent = '✕ Ошибка: ' + ((res && res.error) || 'нет сети');
        }
        setTimeout(() => { btnUpdateRoots.textContent = orig; }, 4000);
      });
    });
  }
});
