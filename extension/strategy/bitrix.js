export default class BitrixStrategy {
  static id = 'bitrix';
  static domain = null;
  static displayName = 'Битрикс';
  static customDomain = true;
  static route(url) { return url.protocol === 'https:'; }
  authForm() { return [...document.querySelectorAll('form[name="form_auth"],form.bx-admin-auth-form')].find(form => form.getClientRects().length && getComputedStyle(form).visibility !== 'hidden'); }
  isAuthPage() {
    return !!this.authForm()?.querySelector('input[name="USER_LOGIN"],input[name="USER_PASSWORD"],input[name="USER_OTP"]');
  }
  fields(visible) {
    const list = [...(this.authForm()?.querySelectorAll('input[name="USER_OTP"]') || [])].filter(visible);
    return list.length === 1 ? list : [];
  }
  loginAction(button) {
    return button.form === this.authForm() && (button.type === 'submit' || /^(войти|продолжить|вход|log\s?in|sign\s?in)$/i.test((button.textContent || button.value || '').trim()));
  }
  authTarget(target) { return target.form === this.authForm(); }
  submit(fields, visible) {
    const form = fields[0]?.form;
    if (!form || form !== this.authForm()) return null;
    // Leave CAPTCHA completion to the user; never submit it empty or retry.
    if ([...form.querySelectorAll('input[name="captcha_word"]')].some(el => visible(el) && !el.value.trim())) return null;
    const buttons = [...form.querySelectorAll('button[type="submit"],button:not([type]),input[type="submit"]')].filter(visible);
    return buttons.length === 1 ? buttons[0] : null;
  }
}
