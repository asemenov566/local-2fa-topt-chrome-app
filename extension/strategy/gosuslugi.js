export default class GosuslugiStrategy {
  static id = 'gosuslugi';
  static domain = 'https://esia.gosuslugi.ru';
  static displayName = 'Госуслуги';
  static customDomain = false;
  static route(url) { return url.origin === this.domain && /^\/login(?:\/|$)/.test(url.pathname); }
  isAuthPage() { return GosuslugiStrategy.route(location); }
  fields(visible) {
    if (!this.isAuthPage() || !/TOTP|код[^.\n]{0,120}из\s+приложени|приложени[^.\n]{0,120}код/i.test(document.body?.innerText || '')) return [];
    const list = [...document.querySelectorAll('input[autocomplete="one-time-code"]')].filter(visible);
    return [1, 6, 8].includes(list.length) ? list : [];
  }
  loginAction(button) { return /^(войти(?:\s.*)?|вход|продолжить)$/i.test((button.textContent || button.value || '').trim()); }
  authTarget(target) { return this.isAuthPage() && !!target.closest('form'); }
  // ESIA continues after the last digit; there is no separate Continue button.
  submit() { return null; }
}
