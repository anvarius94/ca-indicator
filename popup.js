// popup.js - CA Indicator User Interface Logic

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

  let currentTabStatus = null;
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

  try {
    const urlObj = new URL(activeTab.url);
    elSiteDomain.textContent = urlObj.hostname || activeTab.url;

    if (urlObj.protocol === 'chrome:' || urlObj.protocol === 'edge:' || urlObj.protocol === 'about:') {
      renderInternalPage(urlObj.hostname);
      return;
    }
  } catch (e) {
    elSiteDomain.textContent = activeTab.url || 'Неизвестно';
  }

  const elFlagAlert = document.getElementById('flag-alert');
  const btnCopyFlag = document.getElementById('btn-copy-flag');

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

  // Request status from background worker
  chrome.runtime.sendMessage({ type: 'GET_TAB_STATUS', tabId: activeTab.id }, response => {
    if (chrome.runtime.lastError || !response || !response.status) {
      // If webRequest hasn't fired yet or tab reloaded
      renderFallback(activeTab.url);
      return;
    }

    // If we have verified status with valid cert data
    if (response?.status && (response.status.level === 'trusted' || response.status.level === 'danger')) {
      if (elFlagAlert) elFlagAlert.style.display = 'none';
    } else {
      if (elFlagAlert) elFlagAlert.style.display = 'flex';
    }

    currentTabStatus = response?.status || null;
    if (response?.userWhitelist) {
      currentWhitelist = response.userWhitelist;
      renderWhitelist(currentWhitelist);
    }
    renderStatus(currentTabStatus || { level: 'flag_required' });
  });

  function renderStatus(status) {
    elStatusCard.className = `status-card status-${status.level || 'warning'}`;
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
      elLevelBadge.textContent = 'ОБНАРУЖЕН ПЕРЕХВАТ';
      elHeadline.textContent = 'Трафик может расшифровываться!';
      elDesc.textContent = status.riskDescription || 'Сертификат выдан известным центром перехвата или государственным УЦ.';
      btnWhitelist.style.display = 'none';
    } else if (status.level === 'trusted') {
      if (elFlagAlert) elFlagAlert.style.display = 'none';
      elStatusIcon.textContent = '🛡️';
      elLevelBadge.textContent = 'ОБЩЕПРИЗНАННЫЙ УЦ';
      elHeadline.textContent = 'Соединение доверенное';
      elDesc.textContent = status.riskDescription || 'Сертификат выдан мировым удостоверяющим центром из официальных хранилищ.';
      btnWhitelist.style.display = 'none';
    } else if (status.level === 'warning') {
      elStatusIcon.textContent = '⚠️';
      elLevelBadge.textContent = 'НЕИЗВЕСТНЫЙ УЦ';
      elHeadline.textContent = 'Подозрительный сертификат';
      elDesc.textContent = status.riskDescription || 'УЦ отсутствует в списке общепризнанных доверенных центров.';
      btnWhitelist.style.display = 'block';
    } else if (status.level === 'insecure') {
      if (elFlagAlert) elFlagAlert.style.display = 'none';
      elStatusIcon.textContent = '🔓';
      elLevelBadge.textContent = 'НЕТ ШИФРОВАНИЯ';
      elHeadline.textContent = 'Открытое соединение HTTP';
      elDesc.textContent = 'Данные передаются в незашифрованном виде. Любой посредник может их перехватить.';
      btnWhitelist.style.display = 'none';
    }
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

  function renderFallback(url) {
    if (url && url.startsWith('http://')) {
      if (elFlagAlert) elFlagAlert.style.display = 'none';
      renderStatus({
        level: 'insecure',
        issuerName: 'Отсутствует (HTTP)',
        subjectName: elSiteDomain.textContent,
        fingerprint: '—',
        riskDescription: 'Страница загружена по незащищенному протоколу HTTP.'
      });
    } else {
      // Show flag alert prominently!
      if (elFlagAlert) elFlagAlert.style.display = 'flex';
      elStatusCard.className = 'status-card status-warning';
      elStatusIcon.textContent = '⚙️';
      elLevelBadge.textContent = 'ТРЕБУЕТСЯ НАСТРОЙКА CHROME';
      elHeadline.textContent = 'Включите флаг WebRequestSecurityInfo';
      elDesc.textContent = 'Chrome блокирует чтение сертификатов без флага. Скопируйте ссылку выше, переключите в Enabled и перезагрузите браузер.';
      elIssuer.textContent = 'Ожидание флага…';
      elSubject.textContent = elSiteDomain.textContent;
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

  // Whitelist current CA
  btnWhitelist.addEventListener('click', () => {
    if (!currentTabStatus || !currentTabStatus.issuerName) return;
    const nameToAdd = currentTabStatus.issuerName;
    chrome.runtime.sendMessage({ type: 'ADD_WHITELIST', name: nameToAdd }, res => {
      if (res && res.success) {
        currentWhitelist = res.userWhitelist;
        renderWhitelist(currentWhitelist);
        btnWhitelist.style.display = 'none';
        // Re-render as trusted
        currentTabStatus.level = 'trusted';
        currentTabStatus.riskDescription = 'УЦ добавлен вами в белый список доверенных.';
        renderStatus(currentTabStatus);
      }
    });
  });

  function renderWhitelist(list) {
    elWhitelistItems.innerHTML = '';
    if (list.length === 0) {
      elWhitelistItems.innerHTML = '<li style="color: var(--text-muted); font-style: italic;">Список пуст</li>';
      return;
    }

    list.forEach(name => {
      const li = document.createElement('li');
      li.textContent = name;
      const btnDel = document.createElement('button');
      btnDel.className = 'btn-remove-wl';
      btnDel.textContent = '✕';
      btnDel.title = 'Удалить из белого списка';
      btnDel.addEventListener('click', () => {
        chrome.runtime.sendMessage({ type: 'REMOVE_WHITELIST', name }, res => {
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
});
