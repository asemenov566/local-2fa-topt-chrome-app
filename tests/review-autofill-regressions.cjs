const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {chromium} = require('./test-browser.cjs');

const root = path.resolve(__dirname, '..');
const origin = 'https://autofill-review.example.test';

(async () => {
  const extension = path.join(root, 'work/review-autofill-extension-' + Date.now());
  await fs.cp(path.join(root, 'extension'), extension, {recursive: true});
  const manifestPath = path.join(extension, 'manifest.json');
  const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
  manifest.host_permissions = [origin + '/*'];
  await fs.writeFile(manifestPath, JSON.stringify(manifest));
  const context = await chromium.launchPersistentContext(path.join(root, 'work/review-autofill-profile-' + Date.now()), {
    executablePath: process.env.TOTP_CHROMIUM_PATH || chromium.executablePath(),
    headless: true,
    args: ['--load-extension=' + extension, '--disable-extensions-except=' + extension]
  });
  let worker;
  try {
    worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
    const base = worker.url().replace('background.js', '');
    const app = await context.newPage();
    await app.goto(base + 'package.json');
    await app.evaluate(async origin => {
      const vault = await import('./vault.js');
      const security = await import('./security.js');
      const core = await import('./core.js');
      const handle = await (await navigator.storage.getDirectory()).getFileHandle('SYNTHETIC-AUTOFILL-REVIEW.vault', {create: true});
      await vault.attachHandle(handle);
      const key = await vault.createKey('1234');
      const account = core.normalizeAccount({name: 'Synthetic review account', secret: 'JBSWY3DPEHPK3PXP', binding: {service: 'bitrix', origin}});
      await vault.saveVault(await vault.seal([account], key.key, key.salt, 1, 4), null);
      await chrome.storage.local.set({protectedMode: true, sessionLifetime: 300, autoEnabled: true});
      await security.rememberKey(key.key, key.salt, true);
    }, origin);
    await app.goto(base + 'app.html?full=1');
    await app.locator('.code').waitFor({state: 'visible'});
    await context.route(origin + '/**', route => route.fulfill({contentType: 'text/html', body: `
      <form name="form_auth"><input name="USER_LOGIN"><button id="login" type="button">Login</button><div id="otp"></div></form>
      <script>
        window.submits = 0;
        document.querySelector('#login').onclick = () => document.querySelector('#otp').innerHTML = '<input name="USER_OTP"><button type="submit">Continue</button>';
        document.querySelector('form').onsubmit = event => { event.preventDefault(); window.submits++; };
      </script>`}));
    const site = await context.newPage();
    await site.goto(origin + '/login/');
    await worker.evaluate(() => {
      const original = FileSystemFileHandle.prototype.getFile;
      globalThis.reviewReadStarted = false;
      FileSystemFileHandle.prototype.getFile = async function (...args) {
        const file = await original.apply(this, args);
        if (this.name === 'SYNTHETIC-AUTOFILL-REVIEW.vault' && !globalThis.reviewReadStarted) {
          globalThis.reviewReadStarted = true;
          await new Promise(resolve => { globalThis.reviewReleaseRead = resolve; });
        }
        return file;
      };
    });
    await site.locator('#login').click();
    for (let attempt = 0; attempt < 100 && !await worker.evaluate(() => globalThis.reviewReadStarted); attempt++) {
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.equal(await worker.evaluate(() => globalThis.reviewReadStarted), true);
    await app.evaluate(() => chrome.storage.local.set({autoEnabled: false}));
    await worker.evaluate(() => globalThis.reviewReleaseRead());
    // The status response is a barrier behind the pending OTP action and OFF cleanup.
    await app.evaluate(() => chrome.runtime.sendMessage({type: 'status'}));
    await site.evaluate(() => new Promise(resolve => requestAnimationFrame(resolve)));
    assert.equal(await site.locator('[name="USER_OTP"]').inputValue(), '');
    assert.equal(await site.evaluate(() => window.submits), 0);
    assert.equal((await worker.evaluate(() => chrome.scripting.getRegisteredContentScripts())).length, 0);
    console.log('PASS turning autofill OFF during a delayed vault read never fills or submits its late response');
    await app.locator('#settings-button').click();
    await app.locator('#auto-toggle').check();
    await app.locator('#settings-dialog .close').click();
    await app.waitForFunction(() => document.querySelector('#auto-status').textContent.includes('Активна'));
    await site.reload();
    await site.locator('#login').click();
    await site.waitForFunction(() => window.submits === 1);
    assert.match(await site.locator('[name="USER_OTP"]').inputValue(), /^\d{6}$/);
    const completed = await worker.evaluate(async origin => {
      const [tab] = await chrome.tabs.query({url: origin + '/*'});
      const [result] = await chrome.scripting.executeScript({target: {tabId: tab.id}, func: () => ({
        active: globalThis.__gaTotpActive,
        hasRuntimeListeners: chrome.runtime.onMessage.hasListeners()
      })});
      return result.result;
    }, origin);
    assert.deepEqual(completed, {active: false, hasRuntimeListeners: false});
    console.log('PASS successful fill submits exactly once and detaches the content runner and runtime listener');
  } finally {
    try { await worker?.evaluate(() => globalThis.reviewReleaseRead?.()); } catch {}
    await context.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
