// content.js - CA Indicator In-Page Visual Feedback
// Isolated via Shadow DOM to guarantee zero conflict with website styles

(function () {
  // Prevent multiple injections
  if (window.__CA_INDICATOR_INITIALIZED__) return;
  window.__CA_INDICATOR_INITIALIZED__ = true;

  let rootEl = null;
  let shadowRoot = null;
  let currentBanner = null;

  // Configuration (cached locally)
  let config = {
    bannerMode: 'threats_only', // 'threats_only' | 'always' | 'never'
    bannerPosition: 'top_right' // 'top_right' | 'bottom_right'
  };

  // Load preferences
  chrome.storage.local.get(['bannerMode', 'bannerPosition'], res => {
    if (res.bannerMode) config.bannerMode = res.bannerMode;
    if (res.bannerPosition) config.bannerPosition = res.bannerPosition;
  });

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local') {
      if (changes.bannerMode) config.bannerMode = changes.bannerMode.newValue;
      if (changes.bannerPosition) config.bannerPosition = changes.bannerPosition.newValue;
    }
  });

  function getOrCreateShadowRoot() {
    if (shadowRoot) return shadowRoot;
    rootEl = document.createElement('ca-indicator-root');
    rootEl.style.cssText = 'all:initial;position:fixed;z-index:2147483647;pointer-events:none;';
    shadowRoot = rootEl.attachShadow({ mode: 'open' });

    // Inject styles inside Shadow DOM
    const style = document.createElement('style');
    style.textContent = `
      * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      }

      /* Alert Banner for DANGER / MITM (Top of viewport) */
      .ca-danger-banner {
        position: fixed;
        top: 0;
        left: 0;
        right: 0;
        background: linear-gradient(135deg, #b91c1c 0%, #7f1d1d 100%);
        color: #ffffff;
        padding: 12px 20px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 16px;
        box-shadow: 0 4px 20px rgba(185, 28, 28, 0.4);
        border-bottom: 2px solid #f87171;
        pointer-events: auto;
        animation: ca-slide-down 0.35s cubic-bezier(0.16, 1, 0.3, 1) forwards;
      }

      @keyframes ca-slide-down {
        from { transform: translateY(-100%); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
      }

      .ca-danger-content {
        display: flex;
        align-items: center;
        gap: 14px;
        flex: 1;
      }

      .ca-icon-pulse {
        font-size: 24px;
        animation: ca-pulse 1.2s infinite ease-in-out;
        flex-shrink: 0;
      }

      @keyframes ca-pulse {
        0% { transform: scale(1); }
        50% { transform: scale(1.15); }
        100% { transform: scale(1); }
      }

      .ca-text-title {
        font-size: 14px;
        font-weight: 700;
        letter-spacing: 0.3px;
        text-transform: uppercase;
        color: #fecaca;
        margin-bottom: 2px;
      }

      .ca-text-desc {
        font-size: 13px;
        line-height: 1.4;
        color: #ffffff;
      }

      .ca-badge-ca-name {
        background: rgba(0, 0, 0, 0.25);
        padding: 2px 8px;
        border-radius: 4px;
        font-family: monospace;
        font-weight: bold;
        color: #fef08a;
      }

      /* Floating Pill for Warning or Trusted */
      .ca-floating-pill {
        position: fixed;
        pointer-events: auto;
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 8px 14px;
        border-radius: 9999px;
        font-size: 13px;
        font-weight: 500;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.25);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
        animation: ca-fade-in 0.3s ease forwards;
      }

      .ca-pos-top-right {
        top: 20px;
        right: 20px;
      }

      .ca-pos-bottom-right {
        bottom: 20px;
        right: 20px;
      }

      @keyframes ca-fade-in {
        from { opacity: 0; transform: translateY(-8px); }
        to { opacity: 1; transform: translateY(0); }
      }

      .ca-fade-out {
        opacity: 0 !important;
        transform: translateY(-8px) scale(0.95) !important;
        pointer-events: none !important;
      }

      .ca-pill-trusted {
        background: rgba(22, 101, 52, 0.92);
        border: 1px solid rgba(74, 222, 128, 0.4);
        color: #ffffff;
      }

      .ca-pill-warning {
        background: rgba(180, 83, 9, 0.92);
        border: 1px solid rgba(251, 191, 36, 0.4);
        color: #ffffff;
      }

      .ca-close-btn {
        background: transparent;
        border: none;
        color: rgba(255, 255, 255, 0.7);
        font-size: 16px;
        cursor: pointer;
        padding: 4px;
        border-radius: 4px;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: color 0.15s, background 0.15s;
        margin-left: 6px;
      }

      .ca-close-btn:hover {
        color: #ffffff;
        background: rgba(255, 255, 255, 0.15);
      }
    `;
    shadowRoot.appendChild(style);

    // Append root to document once ready
    if (document.body) {
      document.body.appendChild(rootEl);
    } else {
      document.addEventListener('DOMContentLoaded', () => {
        document.body.appendChild(rootEl);
      });
    }

    return shadowRoot;
  }

  // Плашка гаснет сама, чтобы не перекрывать страницу.
  function scheduleFadeOut(pill, delay) {
    setTimeout(() => {
      if (currentBanner !== pill) return;
      pill.classList.add('ca-fade-out');
      setTimeout(() => {
        if (pill.parentNode) pill.remove();
        if (currentBanner === pill) currentBanner = null;
      }, 350);
    }, delay);
  }

  function displayIndicator(status) {
    if (!status || !status.level) return;

    // Старую плашку снимаем ВСЕГДА и до проверок режима. Раньше выход по
    // «только угрозы» + trusted происходил раньше удаления, и красный баннер
    // оставался висеть после того, как вердикт уже сменился на доверенный.
    if (currentBanner && currentBanner.parentNode) {
      currentBanner.parentNode.removeChild(currentBanner);
      currentBanner = null;
    }

    if (config.bannerMode === 'never') return;
    if (config.bannerMode === 'threats_only' && status.level === 'trusted') return;

    const sr = getOrCreateShadowRoot();

    const issuer = status.issuerName || '(неизвестный УЦ)';

    if (status.level === 'danger' || status.level === 'insecure') {
      const isHttp = status.level === 'insecure';
      const banner = document.createElement('div');
      banner.className = 'ca-danger-banner';
      banner.innerHTML = `
        <div class="ca-danger-content">
          <span class="ca-icon-pulse">${isHttp ? '\u{1F513}' : '\u{1F6A8}'}</span>
          <div>
            <div class="ca-text-title">${isHttp
              ? 'Внимание: страница передаётся без шифрования'
              : 'Внимание: ошибка сертификата'}</div>
            <div class="ca-text-desc">${isHttp
              ? 'Соединение по HTTP. Пароли, cookies и содержимое страницы идут открытым текстом — любой посредник в сети может их прочитать и подменить.'
              : 'Издатель: <span class="ca-badge-ca-name">' + escapeHtml(issuer) + '</span>. ' + escapeHtml(status.riskDescription || '')}</div>
          </div>
        </div>
        <button class="ca-close-btn" title="Скрыть предупреждение">✕</button>
      `;

      banner.querySelector('.ca-close-btn').addEventListener('click', () => {
        banner.remove();
        currentBanner = null;
      });

      sr.appendChild(banner);
      currentBanner = banner;
    } else if (status.level === 'warning') {
      // Floating warning pill for Unknown CA
      const pill = document.createElement('div');
      const posClass = config.bannerPosition === 'bottom_right' ? 'ca-pos-bottom-right' : 'ca-pos-top-right';
      pill.className = `ca-floating-pill ca-pill-warning ${posClass}`;
      pill.innerHTML = `
        <span>⚠️</span>
        <span>${status.parseFailed
          ? 'Сертификат не разобран: <strong>' + escapeHtml(issuer) + '</strong>'
          : 'Без Certificate Transparency: <strong>' + escapeHtml(issuer) + '</strong>'}</span>
        <button class="ca-close-btn" title="Закрыть">✕</button>
      `;

      pill.querySelector('.ca-close-btn').addEventListener('click', () => {
        pill.classList.add('ca-fade-out');
        setTimeout(() => pill.remove(), 300);
        currentBanner = null;
      });

      sr.appendChild(pill);
      currentBanner = pill;

      // Держим дольше зелёной: предупреждение важнее, но всё равно не навсегда.
      scheduleFadeOut(pill, 8000);
    } else if (status.level === 'trusted') {
      // Discreet pill for Trusted CA that slides in and fades out
      const pill = document.createElement('div');
      const posClass = config.bannerPosition === 'bottom_right' ? 'ca-pos-bottom-right' : 'ca-pos-top-right';
      pill.className = `ca-floating-pill ca-pill-trusted ${posClass}`;
      pill.innerHTML = `
        <span>${status.whitelisted ? '\u{1F464}' : '\u{1F6E1}\u{FE0F}'}</span>
        <span>${status.whitelisted
          ? 'Разрешено вами для этого домена'
          : 'Доверенный УЦ: <strong>' + escapeHtml(issuer) + '</strong>'}</span>
        <button class="ca-close-btn" title="Закрыть">✕</button>
      `;

      pill.querySelector('.ca-close-btn').addEventListener('click', () => {
        pill.classList.add('ca-fade-out');
        setTimeout(() => pill.remove(), 300);
        currentBanner = null;
      });

      sr.appendChild(pill);
      currentBanner = pill;

      // Auto-fade after 3.2 seconds
      setTimeout(() => {
        if (currentBanner === pill) {
          pill.classList.add('ca-fade-out');
          setTimeout(() => {
            if (pill.parentNode) pill.remove();
            if (currentBanner === pill) currentBanner = null;
          }, 350);
        }
      }, 3200);
    }
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // Listen for push updates from background service worker
  chrome.runtime.onMessage.addListener(msg => {
    if (msg.type === 'CA_STATUS_UPDATE' && msg.payload) {
      displayIndicator(msg.payload);
    }
  });

  // Request initial status from background
  try {
    chrome.runtime.sendMessage({ type: 'GET_TAB_STATUS' }, res => {
      if (res && res.status) {
        displayIndicator(res.status);
      }
    });
  } catch (e) {
    // Background worker not yet ready
  }
})();
