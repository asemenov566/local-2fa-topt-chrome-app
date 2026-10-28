const assert=require('node:assert/strict'),path=require('node:path');
const {chromium,installDeviceKeyBridge}=require('./test-browser.cjs');
(async()=>{
 const extension=path.resolve('extension');
 const context=await chromium.launchPersistentContext(path.resolve('work/session-lifetime-'+Date.now()),{executablePath:process.env.TOTP_CHROMIUM_PATH||chromium.executablePath(),headless:true,args:['--load-extension='+extension,'--disable-extensions-except='+extension]});
 try {
  await installDeviceKeyBridge(context);
  await context.addInitScript(()=>{const connect=chrome.runtime.connect.bind(chrome.runtime);chrome.runtime.connect=options=>{const port=connect(options);if(options?.name==='totp-session-view')globalThis.__testSessionPort=port;return port;};});
  const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker'),id=worker.url().split('/')[2],url='chrome-extension://'+id+'/app.html?full=1';
  let page=await context.newPage();await page.goto('chrome-extension://'+id+'/package.json');
  await page.evaluate(async()=>{const vault=await import('./vault.js');const handle=await(await navigator.storage.getDirectory()).getFileHandle('SYNTHETIC-SESSION.vault',{create:true});await vault.attachHandle(handle);});
  await page.goto(url);await page.locator('#password').fill('1234');await page.waitForFunction(()=>document.querySelector('#pin-prompt').textContent==='Повторите пароль');await page.locator('#password').fill('1234');await page.locator('#codes-screen').waitFor({state:'visible'});
  const before=await page.evaluate(async()=>(await chrome.storage.session.get('uiUnlock')).uiUnlock);
  assert.equal(before.expiresAt-before.authenticatedAt,60000);
  await page.locator('#settings-button').click();assert.equal(await page.locator('#session-lifetime').inputValue(),'60');assert.equal(await page.locator('#protection-toggle').count(),0);
  // A new choice saves immediately but never replaces the currently open session.
  await page.locator('#session-lifetime').selectOption('300');await page.waitForFunction(()=>!document.querySelector('#session-lifetime').disabled);
  const chosen=await page.evaluate(async()=>({local:await chrome.storage.local.get(['sessionLifetime','deviceKey']),unlock:(await chrome.storage.session.get('uiUnlock')).uiUnlock}));
  assert.deepEqual(chosen.local,{sessionLifetime:300});assert.equal(chosen.unlock.expiresAt,before.expiresAt);
  await page.close();page=await context.newPage();await page.goto(url);await page.locator('#codes-screen').waitFor({state:'visible'});
  const reopened=await page.evaluate(async()=>(await chrome.storage.session.get('uiUnlock')).uiUnlock);
  assert.equal(reopened.authenticatedAt,before.authenticatedAt);assert.equal(reopened.expiresAt,before.authenticatedAt+300000);
  const alarm=await worker.evaluate(()=>chrome.alarms.get('totp-session-expiry'));assert.equal(alarm.periodInMinutes,undefined);assert.equal(alarm.scheduledTime,reopened.expiresAt);
  console.log('PASS Default one minute, deferred settings, reopen preserves authentication time and one-shot alarm');
  // Model elapsed authentication time; a shorter policy is applied on close.
  await page.evaluate(async()=>{const {uiUnlock}=await chrome.storage.session.get('uiUnlock');await chrome.storage.session.set({uiUnlock:{...uiUnlock,authenticatedAt:Date.now()-40000}});});
  await page.locator('#settings-button').click();await page.locator('#session-lifetime').selectOption('30');await page.waitForFunction(()=>!document.querySelector('#session-lifetime').disabled);assert.equal(await page.locator('#codes-screen').isVisible(),true);
  await page.close();page=await context.newPage();await page.goto(url);await page.locator('#lock-screen').waitFor({state:'visible'});await page.waitForFunction(()=>!document.body.hasAttribute('data-starting'));
  assert.equal(await page.locator('#codes-screen').isVisible(),false);assert.equal(await page.evaluate(async()=>!!(await chrome.storage.session.get('uiUnlock')).uiUnlock),false);
  await page.locator('#password').fill('1234');await page.locator('#codes-screen').waitFor({state:'visible'});
  console.log('PASS Shorter expired policy takes effect after closing the owner');
  // A stale UI timer cannot lock a newly authenticated session in another view.
  await worker.evaluate(async()=>{globalThis.__testAlarmCreate=chrome.alarms.create;chrome.alarms.create=async()=>{};await chrome.alarms.clear('totp-session-expiry');});
  await page.evaluate(async()=>{
    const send=chrome.runtime.sendMessage.bind(chrome.runtime);globalThis.__testOriginalSend=send;
    chrome.runtime.sendMessage=message=>message?.type==='session-expire'?new Promise(resolve=>{globalThis.__testExpiryHeld=()=>send(message).then(resolve);}):send(message);
    const {uiUnlock}=await chrome.storage.session.get('uiUnlock');await chrome.storage.session.set({uiUnlock:{...uiUnlock,expiresAt:Date.now()+100}});
  });
  await page.waitForFunction(()=>typeof globalThis.__testExpiryHeld==='function');
  const stale=await page.evaluate(async()=>{
    const before=await chrome.storage.session.get(['uiUnlock','lockEpoch']);
    await chrome.storage.session.set({uiUnlock:{...before.uiUnlock,authenticatedAt:Date.now(),expiresAt:Date.now()+60000}});
    await globalThis.__testExpiryHeld();chrome.runtime.sendMessage=globalThis.__testOriginalSend;
    const after=await chrome.storage.session.get(['uiUnlock','lockEpoch']);return {sameEpoch:before.lockEpoch===after.lockEpoch,alive:!!after.uiUnlock};
  });
  assert.deepEqual(stale,{sameEpoch:true,alive:true});assert.equal(await page.locator('#codes-screen').isVisible(),true);
  await worker.evaluate(()=>{chrome.alarms.create=globalThis.__testAlarmCreate;});
  console.log('PASS Stale UI expiry cannot lock a newer authenticated session');
  // Expiry blocks an already open UI without polling or relying on user activity.
  await page.evaluate(async()=>{const {uiUnlock}=await chrome.storage.session.get('uiUnlock');await chrome.storage.session.set({uiUnlock:{...uiUnlock,expiresAt:Date.now()+250}});});
  await page.locator('#lock-screen').waitFor({state:'visible'});assert.equal(await page.evaluate(async()=>!!(await chrome.storage.session.get('uiUnlock')).uiUnlock),false);
  await page.locator('#password').fill('1234');await page.locator('#codes-screen').waitFor({state:'visible'});
  await page.locator('#settings-button').click();await page.locator('#session-lifetime').selectOption('0');await page.waitForFunction(()=>!document.querySelector('#session-lifetime').disabled);
  assert.equal(await page.locator('#passkey-setting').isVisible(),false);
  const wrapped=await page.evaluate(async()=>(await chrome.storage.local.get('deviceKey')).deviceKey);assert.equal(wrapped.protection,'windows-dpapi');assert.equal(wrapped.raw,undefined);
  await page.close();page=await context.newPage();await page.goto(url);await page.locator('#codes-screen').waitFor({state:'visible'});
  assert.equal(await page.evaluate(async()=>(await chrome.storage.session.get('uiUnlock')).uiUnlock.expiresAt),0);
  await page.evaluate(()=>chrome.storage.session.clear());await page.reload();await page.locator('#codes-screen').waitFor({state:'visible'});
  assert.equal(await page.evaluate(async()=>(await chrome.storage.session.get('uiUnlock')).uiUnlock.expiresAt),0);
  await page.locator('#settings-button').click();await page.locator('#session-lifetime').selectOption('300');await page.waitForFunction(()=>!document.querySelector('#session-lifetime').disabled);
  await page.locator('#change-password-open').click();await page.locator('#old-password').waitFor({state:'visible'});assert.equal(await page.locator('#old-password').evaluate(el=>el.required),true);
  console.log('PASS Open UI expires; eternal mode wraps key and reopens after session storage is cleared; finite toggle cannot bypass old password');
  await page.locator('#password-dialog .close').click();await page.locator('#session-lifetime').selectOption('0');await page.waitForFunction(()=>!document.querySelector('#session-lifetime').disabled);
  await page.close();page=await context.newPage();await page.goto(url);await page.locator('#codes-screen').waitFor({state:'visible'});
  await page.evaluate(async()=>{const {uiUnlock}=await chrome.storage.session.get('uiUnlock');await chrome.storage.session.set({uiUnlock:{...uiUnlock,authenticatedAt:Date.now()-40000}});});
  const observer=await context.newPage();await observer.goto(url);await observer.locator('#codes-screen').waitFor({state:'visible'});
  await page.locator('#settings-button').click();await page.locator('#session-lifetime').selectOption('30');await page.waitForFunction(()=>!document.querySelector('#session-lifetime').disabled);
  await page.evaluate(()=>globalThis.__testSessionPort.disconnect());await page.close();
  await observer.locator('#codes-screen').waitFor({state:'hidden'});assert.equal(await observer.evaluate(async()=>!!(await chrome.storage.session.get('uiUnlock')).uiUnlock),false);
  console.log('PASS Closing the owner after losing its port still expires another open eternal view');
 } finally {await context.close();}
})().catch(error=>{console.error(error);process.exitCode=1;});
