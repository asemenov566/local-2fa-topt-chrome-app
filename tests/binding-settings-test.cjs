const fs = require('node:fs/promises');
const path = require('node:path');
const assert = require('node:assert/strict');
const {chromium} = require('./test-browser.cjs');
const root = path.resolve('.');
(async () => {
  const ext = path.join(root,'work/binding-extension-'+Date.now());
  await fs.cp(path.join(root,'extension'),ext,{recursive:true});
  const manifest = JSON.parse(await fs.readFile(path.join(ext,'manifest.json'),'utf8'));
  assert.equal(manifest.host_permissions,undefined);
  manifest.host_permissions = ['https://bitrix.example.test/*','https://auth.openai.com/*'];
  await fs.writeFile(path.join(ext,'manifest.json'),JSON.stringify(manifest));
  const context = await chromium.launchPersistentContext(path.join(root,'work/binding-profile-'+Date.now()),{
    executablePath:process.env.TOTP_CHROMIUM_PATH || chromium.executablePath(),headless:true,
    args:[`--disable-extensions-except=${ext}`,`--load-extension=${ext}`],viewport:{width:480,height:780}
  });
  try {
    const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
    const page = await context.newPage();
    await page.goto(`chrome-extension://${worker.url().split('/')[2]}/app.html?full=1`);
    await page.evaluate(async () => {
      const dir = await navigator.storage.getDirectory();
      await (await import('./vault.js')).attachHandle(await dir.getFileHandle('TEST-ONLY-vault.json',{create:true}));
    });
    await page.reload();
    await page.locator('#pin-length').selectOption('6');
    await page.locator('#password').fill('246813');
    await page.waitForFunction(() => document.querySelector('#pin-prompt').textContent === 'Повторите пароль');
    await page.locator('#password').fill('246813');
    await page.locator('#codes-screen').waitFor({state:'visible'});
    await page.evaluate(() => {
      window.permissionRequests = []; window.allowSites = false;
      chrome.permissions.request = async request => { window.permissionRequests.push(request); return window.allowSites; };
    });
    async function add(name,service,secret) {
      await page.locator('#menu-button').click(); await page.locator('#menu-add').click(); await page.locator('#add-manual').click();
      await page.locator('#account-name').fill(name); await page.locator('#secret').fill(secret); await page.locator('#service').selectOption(service);
      if(service === 'bitrix') await page.locator('#site-url').fill('https://bitrix.example.test/path');
      assert.match(await page.locator('#binding-info').textContent(),/Включите автоподстановку в настройках/);
      await page.locator('#save-account').click(); await page.locator('#import-dialog').waitFor({state:'visible'});
      await page.locator('#commit-import').click(); await page.locator('#import-dialog').waitFor({state:'hidden'});
      assert.match(await page.locator('#toast').textContent(),/Включите автоподстановку в настройках/);
    }
    await add('Synthetic Bitrix','bitrix','JBSWY3DPEHPK3PXP');
    await add('Synthetic OpenAI','openai','GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    assert.deepEqual(await page.evaluate(() => window.permissionRequests),[]);
    let bindings = await worker.evaluate(async () => (await chrome.storage.local.get('autofillBindings')).autofillBindings);
    assert.deepEqual(bindings.map(b => b.service),['bitrix','openai']);
    assert.equal((await worker.evaluate(() => chrome.scripting.getRegisteredContentScripts())).length,0);
    console.log('PASS Save bindings with auto OFF requests no site access and gives enable hint');
    await page.getByRole('button',{name:'Настроить Synthetic Bitrix',exact:true}).click();
    assert.equal(await page.locator('#service').inputValue(),'bitrix');
    await page.locator('#account-name').fill('Renamed synthetic Bitrix'); await page.locator('#save-account').click();
    await page.locator('#edit-dialog').waitFor({state:'hidden'});
    assert.match(await page.locator('#toast').textContent(),/Аккаунт сохранён.*Включите автоподстановку/);
    await page.locator('#settings-button').click(); await page.locator('#auto-toggle').click();
    await page.waitForFunction(() => !document.querySelector('#auto-toggle').checked);
    assert.match(await page.locator('#toast').textContent(),/Привязки сохранены/);
    assert.equal(await worker.evaluate(async () => (await chrome.storage.local.get('autoEnabled')).autoEnabled),false);
    assert.deepEqual(await worker.evaluate(async () => (await chrome.storage.local.get('autofillBindings')).autofillBindings),bindings);
    console.log('PASS Denied site permission leaves mode OFF and bindings intact');
    await page.evaluate(() => {window.allowSites = true;});
    await page.locator('#auto-toggle').check();
    await page.waitForFunction(() => document.querySelector('#auto-status').textContent.includes('Активна'));
    assert.equal((await worker.evaluate(() => chrome.scripting.getRegisteredContentScripts())).length,2);
    await page.locator('#auto-toggle').uncheck();
    await page.waitForFunction(async () => (await chrome.scripting.getRegisteredContentScripts()).length === 0);
    assert.deepEqual(await worker.evaluate(async () => (await chrome.storage.local.get('autofillBindings')).autofillBindings),bindings);
    await page.locator('#auto-toggle').check();
    await page.waitForFunction(() => document.querySelector('#auto-status').textContent.includes('Активна'));
    assert.equal((await worker.evaluate(() => chrome.scripting.getRegisteredContentScripts())).length,2);
    const requests = await page.evaluate(() => window.permissionRequests);
    assert.deepEqual(requests.at(-1).origins,['https://bitrix.example.test/*','https://auth.openai.com/*']);
    console.log('PASS Disable/re-enable preserves saved sites and restores registrations');
  } finally { await context.close(); }
})().catch(error => {console.error(error);process.exitCode = 1;});
