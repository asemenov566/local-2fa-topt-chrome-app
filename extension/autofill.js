// Isolated world. No intervals, network, keys, arbitrary selectors or page-message bridge.
(() => {
  if (globalThis.__gaTotpActive) return;
  globalThis.__gaTotpActive = true;
  let observer, deadline, busy = false, queued = false, armed = false, service = null;
  const visible = el => !el.disabled && !el.readOnly && el.getClientRects().length > 0 && getComputedStyle(el).visibility !== 'hidden';
  function fields() {
    if (service === 'gosuslugi') {
      if (location.origin !== 'https://esia.gosuslugi.ru' || !location.pathname.startsWith('/login') || !/TOTP|код[^.\n]{0,120}из\s+приложени|приложени[^.\n]{0,120}код/i.test(document.body?.innerText || '')) return [];
      const list = [...document.querySelectorAll('input[autocomplete="one-time-code"]')].filter(visible);
      return [1,6,8].includes(list.length) ? list : [];
    }
    const list = [...document.querySelectorAll('input[name="USER_OTP"]')].filter(visible);
    return service === 'bitrix' && list.length === 1 ? list : [];
  }
  function stop() { observer?.disconnect(); observer = null; clearTimeout(deadline); armed = false; }
  async function attempt() {
    queued = false;
    if (!armed || busy || document.hidden) return;
    const list = fields();
    if (!list.length || list.some(el => el.value)) return;
    busy = true;
    try {
      const response = await chrome.runtime.sendMessage({type:'otp-ready',service});
      if (response?.authenticationRequested) { stop(); return; }
      if (!armed || !response?.ok || !/^\d{6}(\d{2})?$/.test(response.code) || response.validUntil <= Date.now() || document.hidden) return;
      const current = fields();
      if (current.length !== list.length || current.some((el,i) => el !== list[i] || el.value) || (current.length > 1 && current.length !== response.code.length)) return;
      stop();
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
      for (let i = 0; i < current.length; i++) {
        const el = current[i], value = current.length === 1 ? response.code : response.code[i];
        setter.call(el,value);
        el.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'insertText',data:value}));
        el.dispatchEvent(new Event('change',{bubbles:true}));
      }
      // Never submit. The site itself may continue after receiving the last digit.
    } catch { stop(); } finally { busy = false; }
  }
  function schedule() { if (!queued && armed) { queued = true; queueMicrotask(attempt); } }
  function arm(s) {
    stop(); service = s; armed = true; schedule();
    observer = new MutationObserver(schedule);
    observer.observe(document.body,{childList:true,subtree:true});
    // Only a bounded transition after the user's login action, not idle polling.
    deadline = setTimeout(stop,15000);
  }
  async function loginAction() {
    try { const r = await chrome.runtime.sendMessage({type:'login-click'}); if (r?.ok && globalThis.__gaTotpActive) arm(r.service); } catch { stop(); }
  }
  function authContext(target) {
    const url = new URL(location.href);
    const loginRoute = /(?:^|\/)(?:login|auth|authorization)(?:\/|$)/i.test(url.pathname) || ['login','login_form','auth'].some(k => /^(yes|y|true|1)$/i.test(url.searchParams.get(k) || ''));
    const form = target.closest?.('form');
    return loginRoute || !!form?.querySelector('input[type="password"],input[name="USER_LOGIN"],input[name="USER_PASSWORD"],input[name="USER_OTP"],input[name="AUTH_FORM"]');
  }
  function alreadyFilled(target) {
    const scope = target.closest?.('form') || document;
    return [...scope.querySelectorAll('input[name="USER_OTP"],input[autocomplete="one-time-code"]')].some(el => visible(el) && el.value);
  }
  function clicked(e) {
    if (!e.isTrusted) return;
    const button = e.target.closest?.('button,input[type="submit"],input[type="button"],a[role="button"]');
    if (!button) return;
    const text = (button.innerText || button.value || button.getAttribute('aria-label') || '').trim();
    const explicitLogin = /^(войти(?:\s.*)?|вход|log\s?in|sign\s?in)$/i.test(text);
    if ((explicitLogin || (/^продолжить$/i.test(text) && authContext(button))) && !alreadyFilled(button)) void loginAction();
  }
  function entered(e) {
    if (e.isTrusted && e.key === 'Enter' && e.target.closest?.('form') && e.target.matches('input:not([type="search"])') && authContext(e.target) && !alreadyFilled(e.target)) void loginAction();
  }
  function visibility() { if (!document.hidden && armed) schedule(); }
  function dispose(message) {
    if (message?.type === 'ga-reset') { stop(); return; }
    if (message?.type === 'ga-resume') { if (globalThis.__gaTotpActive) arm(message.service); return; }
    if (message?.type !== 'ga-disable') return;
    stop(); globalThis.__gaTotpActive = false;
    document.removeEventListener('click',clicked,true); document.removeEventListener('keydown',entered,true); document.removeEventListener('visibilitychange',visibility); window.removeEventListener('pagehide',stop);
    chrome.runtime.onMessage.removeListener(dispose);
  }
  document.addEventListener('click',clicked,true); document.addEventListener('keydown',entered,true); document.addEventListener('visibilitychange',visibility); window.addEventListener('pagehide',stop); chrome.runtime.onMessage.addListener(dispose);
  // One message on navigation: continue only an earlier trusted login click.
  chrome.runtime.sendMessage({type:'pending-login'}).then(r => { if (r?.ok && globalThis.__gaTotpActive) arm(r.service); }).catch(() => {});
})();
