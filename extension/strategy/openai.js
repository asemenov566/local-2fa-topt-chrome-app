export default class OpenAIStrategy {
  static id = 'openai';
  static domain = 'https://auth.openai.com';
  static displayName = 'OpenAI';
  static customDomain = false;
  static route(url, otp = false) {
    return url.origin === this.domain && (otp ? /^\/mfa-challenge(?:\/|$)/ : /^\/(?:log-in|login|u\/login|mfa-challenge)(?:\/|$)/).test(url.pathname);
  }
  isAuthPage() { return OpenAIStrategy.route(location); }
  fields(visible) {
    if (!OpenAIStrategy.route(location,true)) return [];
    // Email/SMS fields also use one-time-code: require the authenticator heading.
    const heading = [...document.querySelectorAll('h1,h2')].map(el => el.textContent).join(' ');
    if (!/приложени[ея]\s+(?:для\s+)?аутентификац|authenticator(?:\s+app)?|authentication\s+app/i.test(heading)) return [];
    const list = [...document.querySelectorAll('form input[name="code"][autocomplete="one-time-code"]')].filter(visible);
    return list.length === 1 ? list : [];
  }
  loginAction(button) {
    return !!button.form && /^(продолжить|войти|continue|log\s?in|sign\s?in)$/i.test((button.textContent || button.value || '').trim());
  }
  authTarget(target) { return this.isAuthPage() && !!target.form; }
  submit(fields, visible) {
    const buttons = [...(fields[0]?.form?.querySelectorAll('button[type="submit"]') || [])].filter(visible);
    return buttons.length === 1 ? buttons[0] : null;
  }
}
