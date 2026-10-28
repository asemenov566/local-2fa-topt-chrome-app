const assert=require('node:assert/strict'),path=require('node:path'),{chromium}=require('./test-browser.cjs');
(async()=>{
 const ext=path.resolve('extension'),context=await chromium.launchPersistentContext(path.resolve('work/qr-export-'+Date.now()),{executablePath:process.env.TOTP_CHROMIUM_PATH||chromium.executablePath(),headless:true,args:['--load-extension='+ext,'--disable-extensions-except='+ext],viewport:{width:390,height:560}});
 try {
  const worker=context.serviceWorkers()[0]||await context.waitForEvent('serviceworker'),id=worker.url().split('/')[2],page=await context.newPage();
  await page.goto('chrome-extension://'+id+'/package.json');
  await page.evaluate(async()=>{const v=await import('./vault.js'),c=await import('./core.js'),h=await(await navigator.storage.getDirectory()).getFileHandle('TEST.vault',{create:true});await v.attachHandle(h);const k=await v.createKey('246813'),records=Array.from({length:14},(_,i)=>c.normalizeAccount({name:'Synthetic '+i,issuer:'Example',secret:c.encode32(new TextEncoder().encode('Synthetic-only-secret-'+i)),algorithm:'SHA1',digits:6,period:i===13?60:30}));await v.saveVault(await v.seal(records,k.key,k.salt,1,k.passwordLength),null);});
  await page.goto('chrome-extension://'+id+'/app.html');await page.locator('#password').fill('246813');await page.locator('#codes-screen').waitFor({state:'visible'});
  assert.equal(await page.locator('h1').innerText(),'Authenticator');await page.locator('#menu-button').click();assert.deepEqual(await page.locator('#menu-dialog .menu-list button').allTextContents(),['Добавить код','Экспорт и резервная копия']);await page.locator('#menu-export').click();
  await page.locator('#export-format').selectOption('qr-google');await page.locator('#download-export').click();assert.match(await page.locator('#export-error').innerText(),/Подтвердите/);
  await page.locator('#plain-consent').check();await page.locator('#download-export').click();assert.match(await page.locator('#export-error').innerText(),/30 секунд/);
  await page.locator('#export-list input').last().uncheck();await page.locator('#download-export').click();await page.locator('#export-qr-dialog').waitFor({state:'visible'});assert.equal(await page.locator('dialog[open]').count(),1);
  const parts=[];do {
   parts.push(await page.evaluate(async()=>{const r=(await import('./qr-reader.js')).createQRReader(),c=document.querySelector('#export-qr');try{const [uri]=await r.decode(c.getContext('2d').getImageData(0,0,c.width,c.height));const p=(await import('./core.js')).parseMigration(uri);return {size:p.size,index:p.index,batch:p.batch,names:p.accounts.map(a=>a.name),periods:p.accounts.map(a=>a.period)};}finally{r.close();}}));
   if(await page.locator('#export-qr-next').isDisabled())break;
   await page.locator('#export-qr-next').click();
  }while(parts.length<100);
  assert.ok(parts.length>1);assert.deepEqual(parts.flatMap(p=>p.names),Array.from({length:13},(_,i)=>'Synthetic '+i));assert.equal(new Set(parts.map(p=>p.batch)).size,1);parts.forEach((p,i)=>{assert.equal(p.size,parts.length);assert.equal(p.index,i);assert.ok(p.periods.every(n=>n===30));});
  await page.locator('#export-qr-dialog .close').first().click();assert.equal(await page.locator('#export-qr').evaluate(c=>c.width),0);
  await page.locator('#menu-button').click();await page.locator('#menu-export').click();await page.locator('#select-all').uncheck();await page.locator('#export-list input').last().check();await page.locator('#export-format').selectOption('qr-single');await page.locator('#plain-consent').check();await page.locator('#download-export').click();
  const period=await page.evaluate(async()=>{const r=(await import('./qr-reader.js')).createQRReader(),c=document.querySelector('#export-qr');try{const [uri]=await r.decode(c.getContext('2d').getImageData(0,0,c.width,c.height));return (await import('./core.js')).parseOtp(uri).period;}finally{r.close();}});assert.equal(period,60);
  await page.evaluate(()=>document.querySelector('#lock-button').click());await page.locator('#lock-screen').waitFor({state:'visible'});assert.equal(await page.locator('#export-qr').evaluate(c=>c.width),0);assert.equal(await page.locator('#export-qr-dialog').isVisible(),false);
  console.log('PASS Minimal menu/title; selected-account Google multipart QR roundtrip; non30 guarded; individual QR preserves period; close/lock clears QR');
 }finally{await context.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
