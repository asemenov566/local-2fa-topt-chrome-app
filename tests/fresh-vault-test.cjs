const assert = require('node:assert/strict');
const path = require('node:path');
const {chromium} = require('./test-browser.cjs');

(async () => {
  const extension = path.resolve('extension');
  const context = await chromium.launchPersistentContext(path.resolve('work/fresh-vault-' + Date.now()), {
    executablePath: process.env.TOTP_CHROMIUM_PATH || chromium.executablePath(),
    headless: true,
    args: ['--load-extension=' + extension, '--disable-extensions-except=' + extension],
    viewport: {width:390,height:560}
  });
  try {
    const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
    const base = 'chrome-extension://' + worker.url().split('/')[2] + '/';
    const errors = [];
    for (const password of ['1234','123456']) {
      const page = await context.newPage();
      page.on('pageerror', error => errors.push(error.message));
      await page.goto(base + 'package.json');
      await page.evaluate(async length => {
        const vault = await import('./vault.js');
        const file = await (await navigator.storage.getDirectory()).getFileHandle('FRESH-' + length + '.vault',{create:true});
        await vault.attachHandle(file);
        await chrome.storage.local.set({
          protectedMode:false, autoEnabled:true,
          deviceKey:{salt:'synthetic-stale',key:'synthetic-stale'},
          passkeyConfig:{credentialId:'synthetic-stale'},
          vaultMeta:{revision:1,token:'synthetic-stale'},
          passwordAttemptGate:{synthetic:{failures:3,blockedUntil:Date.now()+60000}},
          autofillBindings:[{id:'synthetic',origin:'https://example.invalid',service:'bitrix'}]
        });
        await chrome.storage.session.set({
          uiUnlock:{salt:'synthetic-stale',key:'synthetic-stale'},
          autofillSession:{accounts:[],token:'synthetic-stale'},
          loginIntents:{synthetic:{until:Date.now()+60000}},
          authRequest:{until:Date.now()+60000},
          importWindowDrafts:{synthetic:true},lockEpoch:1
        });
      },password.length);
      await page.goto(base + 'app.html');
      await page.waitForFunction(() => !document.body.hasAttribute('data-starting'));
      assert.equal(await page.locator('#pin-length').inputValue(),'4');
      assert.equal(await page.locator('#pin-dots .pin-dot').count(),4);
      assert.equal(await page.locator('#pin-length').isVisible(),true);
      assert.equal(await page.locator('#unlock-passkey').isVisible(),false);
      assert.equal(await page.locator('#protection-toggle').isChecked(),false);
      assert.equal(await page.locator('#passkey-toggle').isChecked(),false);
      const clean = await page.evaluate(async () => {
        const local = await chrome.storage.local.get(null), session = await chrome.storage.session.get(null);
        return {
          protected:local.protectedMode === true, autoOff:local.autoEnabled === false,
          noBindings:local.autofillBindings.length === 0,
          noLocalSecrets:['deviceKey','passkeyConfig','vaultMeta','passwordAttemptGate'].every(k => !(k in local)),
          noSessionSecrets:['uiUnlock','autofillSession','loginIntents','authRequest','importWindowDrafts'].every(k => !(k in session)),
          epochAdvanced:session.lockEpoch > 1,
          noScripts:(await chrome.scripting.getRegisteredContentScripts()).length === 0,
          empty:await (await import('./vault.js')).loadVault() === null
        };
      });
      assert.ok(Object.values(clean).every(Boolean),'Fresh-vault initialization must discard stale unlock state and enforce protection');
      await page.locator('#pin-length').selectOption(String(password.length));
      await page.locator('#password').fill(password);
      await page.locator('#pin-prompt').filter({hasText:'Повторите пароль'}).waitFor();
      await page.locator('#password').fill(password);
      await page.locator('#codes-screen').waitFor({state:'visible'});
      assert.equal(await page.evaluate(async () => (await (await import('./vault.js')).loadVault()).passwordLength),password.length);
      await page.locator('#lock-button').click();
      await page.waitForFunction(length => document.querySelectorAll('#pin-dots .pin-dot').length === length && !document.querySelector('#password').disabled,password.length);
      await page.locator('#password').fill(password);
      await page.locator('#codes-screen').waitFor({state:'visible'});
      await page.close();
    }

    const failure = await context.newPage();
    failure.on('pageerror', error => errors.push(error.message));
    await failure.goto(base + 'app.html');
    await failure.locator('#codes-screen').waitFor({state:'visible'});
    for (const outcome of ['denied','rejected']) {
      await failure.evaluate(async outcome => {
        await chrome.storage.local.set({protectedMode:false,deviceKey:{fixture:'stale-reset-failure'},passkeyConfig:{fixture:true}});
        const file = await (await navigator.storage.getDirectory()).getFileHandle('FRESH-6.vault');
        const writable = await file.createWritable();
        await writable.write(''); await writable.close();
        globalThis.originalResetSend = chrome.runtime.sendMessage.bind(chrome.runtime);
        chrome.runtime.sendMessage = (message,...args) => {
          if (message?.type === 'prepare-new-vault') {
            return outcome === 'denied'
              ? Promise.resolve({ok:false,error:'Synthetic preparation failure'})
              : Promise.reject(new Error('Synthetic preparation transport failure'));
          }
          return originalResetSend(message,...args);
        };
      },outcome);
      await failure.locator('#lock-button').click();
      await failure.locator('#lock-alert').waitFor({state:'visible'});assert.match(await failure.locator('#lock-alert-message').innerText(),/Synthetic preparation/);
      assert.equal(await failure.locator('body').evaluate(e => e.classList.contains('pin-auth')),true);
      assert.equal(await failure.locator('#unlock-form').isVisible(),false);
      assert.equal(await failure.locator('#unlock-passkey').isVisible(),false);
      assert.equal(await failure.locator('#password').isDisabled(),true);
      assert.equal(await failure.locator('#lock-description').isVisible(),false);assert.equal(await failure.locator('.file-controls').isVisible(),false);assert.equal(await failure.locator('#settings-button').isVisible(),false);
      assert.equal(await failure.locator('#lock-retry').isVisible(),true);
      const refused = await failure.evaluate(async () => {
        // Exercise the submission guard too: a failed reset must not create a vault
        // under the previous convenience-mode settings, even if an event is queued.
        for (let i=0;i<2;i++) {
          document.getElementById('password').value = '2468';
          document.getElementById('unlock-form').dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));
        }
        const local = await chrome.storage.local.get(['protectedMode','deviceKey']);
        return {empty:await (await import('./vault.js')).loadVault() === null,local};
      });
      assert.deepEqual(refused,{empty:true,local:{protectedMode:false,deviceKey:{fixture:'stale-reset-failure'}}});

      await failure.evaluate(() => {chrome.runtime.sendMessage = originalResetSend;});
      await failure.locator('#lock-retry').click();
      await failure.waitForFunction(() => document.body.classList.contains('pin-auth') && !document.getElementById('password').disabled && !document.getElementById('pin-length-label').hidden);
      const recovered = await failure.evaluate(() => chrome.storage.local.get(['protectedMode','deviceKey','passkeyConfig']));
      assert.deepEqual(recovered,{protectedMode:true});
      await failure.locator('#password').fill('2468');
      await failure.waitForFunction(() => document.getElementById('pin-prompt').textContent === 'Повторите пароль');
      await failure.locator('#password').fill('2468');
      await failure.locator('#codes-screen').waitFor({state:'visible'});
    }
    await failure.close();

    // Use an inert trusted extension page to isolate the worker operation from UI listeners.
    const control = await context.newPage();
    await control.route(base + 'app.html?fixture=existing',route => route.fulfill({contentType:'text/html',body:'<!doctype html><title>Synthetic existing vault</title>'}));
    await control.goto(base + 'app.html?fixture=existing');
    const preserved = await control.evaluate(async () => {
      await chrome.storage.local.set({protectedMode:false,autoEnabled:false,deviceKey:{fixture:true},passkeyConfig:{fixture:true},vaultMeta:{fixture:true},theme:'dark',layout:'tiles'});
      await chrome.storage.session.set({uiUnlock:{fixture:true},importWindowDrafts:{fixture:true}});
      await chrome.runtime.sendMessage({type:'status'});
      const before = {local:await chrome.storage.local.get(null),session:await chrome.storage.session.get(null)};
      const reply = await chrome.runtime.sendMessage({type:'prepare-new-vault'});
      const after = {local:await chrome.storage.local.get(null),session:await chrome.storage.session.get(null)};
      return {ok:reply?.ok === true,exists:reply?.exists === true,unchanged:JSON.stringify(before) === JSON.stringify(after)};
    });
    assert.deepEqual(preserved,{ok:true,exists:true,unchanged:true});
    assert.deepEqual(errors,[]);
    console.log('PASS fresh vault removes stale unlock state, restores protected 4-dot setup, creates and unlocks 4/6-character vaults; failed preparation blocks creation and recovers on retry; existing vault preserves settings and keys');
  } finally {
    await context.close();
  }
})().catch(error => {console.error(error);process.exitCode=1;});
