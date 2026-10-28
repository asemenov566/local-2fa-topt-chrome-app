const assert=require('node:assert/strict'),path=require('node:path'),{chromium,installDeviceKeyBridge}=require('./test-browser.cjs');
(async()=>{
 const ext=path.resolve('extension'),context=await chromium.launchPersistentContext(path.resolve('work/pin-ui-'+Date.now()),{executablePath:process.env.TOTP_CHROMIUM_PATH||chromium.executablePath(),headless:true,args:['--load-extension='+ext,'--disable-extensions-except='+ext],viewport:{width:390,height:560}});
 try{await installDeviceKeyBridge(context);
  const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker'),id=worker.url().split('/')[2],url='chrome-extension://'+id+'/app.html',page=await context.newPage();
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.goto('chrome-extension://'+id+'/package.json');
  await page.evaluate(async()=>{const v=await import('./vault.js'),h=await(await navigator.storage.getDirectory()).getFileHandle('PIN-TEST.vault',{create:true});await v.attachHandle(h);});
  await page.goto(url);await page.waitForFunction(()=>!document.body.hasAttribute('data-starting'));
  assert.equal(await page.locator('#pin-length').inputValue(),'4');assert.equal(await page.locator('#pin-dots .pin-dot').count(),4);assert.equal(await page.locator('#password').getAttribute('type'),'password');
  assert.equal(await page.locator('#password').evaluate(e=>getComputedStyle(e).opacity),'0');
  assert.equal(await page.locator('body').evaluate(e=>e.getBoundingClientRect().height),240);
  await page.setViewportSize({width:390,height:240});
  async function centeredDots(){const p=await page.locator('#pin-dots').boundingBox();assert.ok(Math.abs(p.x+p.width/2-195)<=1);assert.ok(Math.abs(p.y+p.height/2-120)<=1);}
  await centeredDots();
  for(const sel of ['#menu-button','#settings-button','#window-button','.vault-logo','#lock-title','#lock-description','#unlock-button'])assert.equal(await page.locator(sel).isVisible(),false);
  await page.locator('#password').fill('1234');await page.locator('#pin-prompt').filter({hasText:'Повторите пароль'}).waitFor();await page.locator('#password').fill('4321');await page.getByText('Пароли не совпадают.',{exact:true}).waitFor();assert.equal(await page.locator('#pin-dots .filled').count(),0);
  assert.equal(await page.evaluate(async()=>await(await import('./vault.js')).loadVault()),null);
  await page.locator('#password').fill('1234');await page.locator('#pin-prompt').filter({hasText:'Повторите пароль'}).waitFor();await page.locator('#password').fill('1234');await page.locator('#codes-screen').waitFor({state:'visible'});
  assert.equal(await page.evaluate(async()=>(await(await import('./vault.js')).loadVault()).passwordLength),4);
  assert.equal(await page.locator('body').evaluate(e=>e.getBoundingClientRect().height)>=560,true);
  await page.setViewportSize({width:390,height:560});await page.locator('#settings-button').click();assert.equal(await page.locator('#protection-toggle').isChecked(),false);assert.match(await page.locator('label').filter({has:page.locator('#protection-toggle')}).innerText(),/Не запрашивать пароль/);
  await page.locator('#protection-toggle').check();await page.waitForFunction(()=>document.querySelector('#toast').textContent==='Автоматическое открытие включено'||document.querySelector('#settings-error').textContent);assert.equal(await page.locator('#settings-error').innerText(),'');await page.locator('#settings-dialog .close').click();await page.locator('#settings-button').click();await page.locator('#protection-toggle').uncheck();await page.waitForFunction(()=>!document.querySelector('#password').disabled&&document.querySelector('#toast').textContent==='Ключ устройства удалён. Защита включена.');await page.setViewportSize({width:390,height:240});await centeredDots();
  const toastColors=[];for(const colorScheme of ['light','dark']){await page.emulateMedia({colorScheme});const t=await page.evaluate(()=>{const r=s=>{const p=document.querySelector(s).getBoundingClientRect();return{top:p.top,bottom:p.bottom};};return{toast:r('#toast'),form:r('#unlock-form'),footer:r('footer'),background:getComputedStyle(document.querySelector('#toast')).backgroundColor,hidden:document.querySelector('#toast').hidden};});assert.equal(t.hidden,false);assert.ok(t.toast.top>=t.form.bottom,'Toast below passcode form');assert.ok(t.toast.bottom<=t.footer.top,'Toast above footer');const rgba=t.background.match(/[\d.]+/g).map(Number);assert.equal(rgba.length,4);assert.ok(rgba.slice(0,3).every(n=>n<130)&&rgba[3]>0&&rgba[3]<1);toastColors.push(t.background);}assert.equal(toastColors[0],toastColors[1]);await page.emulateMedia({colorScheme:'light'});

  await page.locator('#password').fill('12');assert.equal(await page.locator('#pin-dots .filled').count(),2);
  await page.locator('header h1').click();assert.equal(await page.locator('#password').evaluate(e=>document.activeElement===e&&e.selectionStart===2&&e.selectionEnd===2),true);
  for(let i=1;i<=3;i++){
   await page.locator('#password').fill('9999');
   await page.waitForFunction(async n=>{const g=(await chrome.storage.local.get('passwordAttemptGate')).passwordAttemptGate;return Object.values(g||{}).some(x=>x.failures===n);},i);
   await page.waitForFunction(()=>document.querySelector('#password').value==='');
   if(i<3)await page.waitForFunction(()=>!document.querySelector('#password').disabled);
  }
  assert.equal(await page.locator('#password').isDisabled(),true);assert.equal(await page.locator('#pin-dots .filled').count(),0);assert.match(await page.locator('#pin-prompt').innerText(),/Повторите через/);
  const blockedUntil=await page.evaluate(async()=>Object.values((await chrome.storage.local.get('passwordAttemptGate')).passwordAttemptGate)[0].blockedUntil);
  const second=await context.newPage();await second.goto(url);await second.waitForFunction(()=>!document.body.hasAttribute('data-starting'));assert.equal(await second.locator('#password').isDisabled(),true);await second.close();
  await page.reload();await page.waitForFunction(()=>!document.body.hasAttribute('data-starting'));assert.equal(await page.locator('#password').isDisabled(),true);
  await page.setViewportSize({width:390,height:240});await page.screenshot({path:'outputs/pin-blocked-1.4.0.png'});await page.setViewportSize({width:390,height:560});
  await page.evaluate(time=>{Date.now=()=>time;document.dispatchEvent(new Event('visibilitychange'));},blockedUntil+1);
  await page.waitForFunction(()=>!document.querySelector('#password').disabled);await page.locator('#password').fill('1234');await page.locator('#codes-screen').waitFor({state:'visible'});
  assert.equal(await page.evaluate(async()=>Object.keys((await chrome.storage.local.get('passwordAttemptGate')).passwordAttemptGate||{}).length),0);
  await page.locator('#settings-button').click();await page.locator('#change-password-open').click();await page.locator('#new-password-length').selectOption('6');await page.locator('#new-password').fill('ABC123');await page.locator('#new-password-confirm').fill('ABC123');await page.locator('#change-password-form .primary').click();await page.locator('#password-dialog').waitFor({state:'hidden'});await page.locator('#settings-dialog .close').click();
  const metadata=await page.evaluate(async()=>{const v=await import('./vault.js'),file=await v.loadVault();let oldFails=false;try{await v.unseal(file,'1234');}catch{oldFails=true;}return {length:file.passwordLength,oldFails,opens:(await v.unseal(file,'ABC123')).accounts.length===0};});assert.deepEqual(metadata,{length:6,oldFails:true,opens:true});
  await page.locator('#lock-button').click();await page.waitForFunction(()=>document.querySelectorAll('#pin-dots .pin-dot').length===6&&!document.querySelector('#password').disabled);
  await page.locator('#password').fill('ABC');assert.equal(await page.locator('#pin-dots .filled').count(),3);await page.setViewportSize({width:390,height:240});await centeredDots();await page.screenshot({path:'outputs/pin-entry-1.4.0.png'});await page.locator('#password').fill('ABC123');await page.locator('#codes-screen').waitFor({state:'visible'});
  assert.deepEqual(errors,[]);
  console.log('PASS 240px hidden-input 4/6 passcodes, confirmation, automatic login, focus-at-end, shared persistent 3-attempt cooldown, expiry, password-change re-encryption and metadata');
 }catch(error){for(const diagnostic of context.pages())if(diagnostic.url().includes('/app.html'))console.error('PIN UI diagnostic',await diagnostic.evaluate(()=>({starting:document.body.hasAttribute('data-starting'),startup:document.querySelector('#startup-message')?.textContent,alert:document.querySelector('#lock-alert-message')?.textContent,settings:document.querySelector('#settings-error')?.textContent,toast:document.querySelector('#toast')?.textContent,disabled:document.querySelector('#protection-toggle')?.disabled})));throw error;}finally{await context.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
