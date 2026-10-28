const assert = require('node:assert/strict');
const path = require('node:path');
const {chromium} = require('./test-browser.cjs');

(async () => {
  const extension = path.resolve('extension');
  const context = await chromium.launchPersistentContext(path.resolve('work/pin-lock-race-' + Date.now()), {
    executablePath: process.env.TOTP_CHROMIUM_PATH || chromium.executablePath(),
    headless: true,
    args: ['--load-extension=' + extension, '--disable-extensions-except=' + extension],
    viewport: {width: 390, height: 560}
  });
  try {
    const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
    const base = 'chrome-extension://' + worker.url().split('/')[2] + '/';
    const page = await context.newPage();
    await page.goto(base + 'package.json');
    await page.evaluate(async () => {
      const vault = await import('./vault.js');
      const {normalizeAccount} = await import('./core.js');
      const handle = await (await navigator.storage.getDirectory()).getFileHandle('SYNTHETIC-PIN-LOCK-RACE.vault', {create: true});
      await vault.attachHandle(handle);
      const created = await vault.createKey('1234');
      const account = normalizeAccount({issuer: 'Synthetic review', name: 'Lock race', secret: 'JBSWY3DPEHPK3PXP'});
      await vault.saveVault(await vault.seal([account], created.key, created.salt, 1, 4), null);
      await chrome.storage.local.set({passkeyConfig: {version: 1, salt: created.salt, credential: 'AAAA', prfSalt: 'AAAA'}});
    });
    await page.goto(base + 'app.html');
    await page.waitForFunction(() => !document.body.hasAttribute('data-starting'));
    await page.locator('#password').fill('1234');
    await page.locator('.code').waitFor({state: 'visible'});

    const other = await context.newPage();
    await other.goto(base + 'app.html');
    await other.locator('.code').waitFor({state: 'visible'});
    await page.evaluate(() => {
      globalThis.race = {held: false, released: false, replacementReady: false, authReads: 0, credentialCalls: 0};
      const query = FileSystemFileHandle.prototype.queryPermission;
      let holdFirst = true;
      FileSystemFileHandle.prototype.queryPermission = async function (...args) {
        const result = await query.apply(this, args);
        if (holdFirst) {
          holdFirst = false;
          race.held = true;
          await new Promise(resolve => { race.release = () => { race.released = true; resolve(); }; });
        }
        return result;
      };
      const getLocal = chrome.storage.local.get.bind(chrome.storage.local);
      chrome.storage.local.get = async (...args) => {
        const result = await getLocal(...args);
        if (args[0] === 'passwordAttemptGate' && race.held && !race.released) {
          // The next task runs after refreshPinGate and configureLock finish their microtasks.
          setTimeout(() => { race.replacementReady = true; }, 0);
        }
        return result;
      };
      const getSession = chrome.storage.session.get.bind(chrome.storage.session);
      chrome.storage.session.get = (...args) => {
        if (args[0] === 'lockEpoch') race.authReads++;
        return getSession(...args);
      };
      navigator.credentials.get = async () => { race.credentialCalls++; throw new Error('Synthetic credential must not be requested while locking'); };
    });

    await page.locator('#lock-button').click();
    await page.waitForFunction(() => race.held);
    assert.equal(await page.locator('#password').isDisabled(), true);
    assert.equal(await page.locator('#unlock-passkey').isDisabled(), true);

    // A different window can select a vault while the original permission/read check is slow.
    // Its notification starts a newer configureLock that finishes before the original one.
    await other.evaluate(() => chrome.storage.local.set({vaultFileChanged: crypto.randomUUID()}));
    await page.waitForFunction(() => race.replacementReady);
    assert.equal(await page.locator('#password').isDisabled(), true, 'A newer configureLock must not enable PIN while the original lock request is pending');
    assert.equal(await page.locator('#unlock-passkey').isDisabled(), true);

    const guarded = await page.evaluate(() => {
      const input = document.getElementById('password');
      input.value = '1234';
      input.dispatchEvent(new Event('input', {bubbles: true}));
      const inputWasCleared = input.value === '';
      input.value = '1234';
      document.getElementById('unlock-form').dispatchEvent(new Event('submit', {bubbles: true, cancelable: true}));
      document.getElementById('unlock-passkey').dispatchEvent(new MouseEvent('click', {bubbles: true}));
      input.value = '';
      return {inputWasCleared, authReads: race.authReads, credentialCalls: race.credentialCalls};
    });
    assert.deepEqual(guarded, {inputWasCleared: true, authReads: 0, credentialCalls: 0});
    assert.equal(await page.locator('.code').count(), 0);
    assert.deepEqual(await other.evaluate(() => chrome.runtime.sendMessage({type: 'lock'})), {ok: true});
    assert.equal(await page.evaluate(async () => (await chrome.storage.session.get('manualLock')).manualLock), true);
    assert.equal(await page.locator('#codes-screen').isVisible(), false);

    await page.evaluate(() => race.release());
    await page.waitForFunction(() => !document.getElementById('password').disabled && document.activeElement.id === 'password');
    await page.keyboard.insertText('12');
    await page.evaluate(() => chrome.storage.local.get('vaultMeta'));
    assert.equal(await page.locator('#password').inputValue(), '12', 'The completed older configuration must not erase new input');
    await page.keyboard.insertText('34');
    await page.locator('.code').waitFor({state: 'visible'});
    assert.deepEqual(await other.evaluate(() => chrome.runtime.sendMessage({type: 'lock'})), {ok: true});
    await page.locator('#codes-screen').waitFor({state: 'hidden'});
    assert.equal(await page.locator('.code').count(), 0);
    const session = await page.evaluate(() => chrome.storage.session.get(['manualLock', 'uiUnlock']));
    assert.equal(session.manualLock, true);
    assert.equal(session.uiUnlock, undefined);
    console.log('PASS Superseded lock configuration cannot enable PIN/passkey early; input survives completion and another window still locks visible codes');
  } finally {
    await context.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
