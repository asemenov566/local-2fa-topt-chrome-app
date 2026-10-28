// Bundled with exactly one site strategy. Runs in the isolated content world.
export function start(strategy) {
  const serviceId = strategy.constructor.id;
  if (globalThis.__gaTotpActive || !strategy.isAuthPage()) return;
  // Ordinary pages exit above: no messages, listeners, observers or timers.
  globalThis.__gaTotpActive = true;
  let observer, deadline, busy = false, queued = false, rerun = false, armed = false, generation = 0;
  const visible = el => el.isConnected && !el.disabled && !el.readOnly && el.getClientRects().length > 0 && getComputedStyle(el).visibility !== 'hidden';
  const fields = () => strategy.isAuthPage() ? strategy.fields(visible) : [];
  const sameOrigin = form => !form || new URL(form.getAttribute('action') || location.href,location.href).origin === location.origin;
  function stop() { observer?.disconnect(); observer = null; clearTimeout(deadline); armed = false; generation++; }
  async function attempt() {
    queued = false;
    if (!armed || busy || document.hidden) return;
    if (!strategy.isAuthPage()) { dispose({type:'ga-disable'}); return; }
    const list = fields();
    if (!list.length || list.some(el => el.value || !sameOrigin(el.form))) return;
    busy = true;
    const token = generation, url = location.href;
    try {
      const response = await chrome.runtime.sendMessage({type:'otp-ready',service:serviceId});
      if (token !== generation) return;
      if (response?.authenticationRequested) { stop(); return; }
      if (!armed || !response?.ok || response.service !== serviceId || !/^\d{6}(\d{2})?$/.test(response.code) || response.validUntil <= Date.now() || document.hidden || location.href !== url) return;
      const current = fields();
      if (current.length !== list.length || current.some((el,i) => el !== list[i] || el.value || !sameOrigin(el.form)) || (current.length > 1 && current.length !== response.code.length)) return;
      stop();
      const completed = generation, form = current[0].form;
      let submitted = false;
      const onSubmit = () => { submitted = true; };
      form?.addEventListener('submit',onSubmit,true);
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set;
      for (let i = 0; i < current.length; i++) {
        const el = current[i], value = current.length === 1 ? response.code : response.code[i];
        setter.call(el,value);
        el.dispatchEvent(new InputEvent('input',{bubbles:true,inputType:'insertText',data:value}));
        el.dispatchEvent(new Event('change',{bubbles:true}));
      }
      // Allow input handlers to update UI, then click once without retry/polling.
      queueMicrotask(() => {
        try {
          if (submitted || completed !== generation || !globalThis.__gaTotpActive || document.hidden || location.href !== url || response.validUntil <= Date.now()) return;
          const now = fields();
          if (now.length !== current.length || now.some((el,i) => el !== current[i] || el.value !== (now.length === 1 ? response.code : response.code[i]) || !sameOrigin(el.form))) return;
          const button = strategy.submit(now,visible);
          if (button && visible(button) && button.form === form && sameOrigin(form)) button.click();
        } finally { form?.removeEventListener('submit',onSubmit,true); dispose({type:'ga-disable'}); }
      });
    } catch { stop(); } finally { busy = false; if (rerun) { rerun = false; schedule(); } }
  }
  function schedule() {
    if (!armed) return;
    if (busy) { rerun = true; return; }
    if (!queued) { queued = true; queueMicrotask(attempt); }
  }
  function arm(service) {
    if (service !== serviceId || !strategy.isAuthPage()) return;
    stop(); armed = true; schedule();
    observer = new MutationObserver(schedule);
    observer.observe(document.body,{childList:true,subtree:true});
    deadline = setTimeout(stop,15000);
  }
  async function loginAction() {
    const token = generation;
    try { const r = await chrome.runtime.sendMessage({type:'login-click'}); if (r?.ok && token === generation && globalThis.__gaTotpActive) arm(r.service); } catch { stop(); }
  }
  function alreadyFilled() { return fields().some(el => el.value); }
  function clicked(e) {
    if (!e.isTrusted) return;
    if (!strategy.isAuthPage()) { dispose({type:'ga-disable'}); return; }
    const button = e.target.closest?.('button,input[type="submit"],input[type="button"],a[role="button"]');
    if (button && strategy.loginAction(button) && !alreadyFilled()) {
      // On an already-open OTP form, do not send an empty code while awaiting
      // the worker. Password/login form submission remains entirely native.
      if (fields().some(el => el.form === button.form && sameOrigin(el.form))) e.preventDefault();
      void loginAction();
    }
  }
  function entered(e) {
    if (e.isTrusted && e.key === 'Enter' && e.target.matches('input:not([type="search"])') && strategy.isAuthPage() && strategy.authTarget(e.target) && !alreadyFilled()) {
      if (fields().some(el => el.form === e.target.form && sameOrigin(el.form))) e.preventDefault();
      void loginAction();
    }
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
  chrome.runtime.sendMessage({type:'pending-login'}).then(r => { if (r?.ok && globalThis.__gaTotpActive) arm(r.service); }).catch(() => {});
}
